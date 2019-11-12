// Copyright 2013-2014 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// PKCS#11 s11.11: Signing and MACing functions
//   C_SignInit
//   C_Sign
//   C_SignUpdate
//   C_SignFinal
//   C_SignRecoverInit
//   C_SignRecover
// PKCS#11 s11.12: Functions for verifying signatures and MACs
//   C_VerifyInit
//   C_Verify
//   C_VerifyUpdate
//   C_VerifyFinal
//   C_VerifyRecoverInit
//   C_VerifyRecover
#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

namespace {

class SignTest : public ReadOnlySessionTest,
                 public ::testing::WithParamInterface<string> {
 public:
  SignTest()
    : info_(kSignatureInfo[GetParam()]),
      public_attrs_({CKA_VERIFY}),
      private_attrs_({CKA_SIGN}),
      keypair_(session_, public_attrs_, private_attrs_),
      datalen_(std::rand() % info_.max_data),
      data_(randmalloc(datalen_)),
      mechanism_({info_.alg, NULL_PTR, 0}) {
  }
 protected:
  SignatureInfo info_;
  vector<CK_ATTRIBUTE_TYPE> public_attrs_;
  vector<CK_ATTRIBUTE_TYPE> private_attrs_;
  KeyPair keypair_;
  const int datalen_;
  unique_ptr<CK_BYTE, freer> data_;
  CK_MECHANISM mechanism_;
};

class ECSignTest : public ReadOnlySessionTest,
                 public ::testing::WithParamInterface<string> {
 public:
  ECSignTest()
    : info_(kCurveInfo[GetParam()]),
      public_attrs_({CKA_VERIFY}),
      private_attrs_({CKA_SIGN}),
      keypair_(session_, public_attrs_, private_attrs_, hex_decode(info_.params),
               info_.keygen_mechanism, info_.key_type),
      datalen_(32),
      data_(randmalloc(datalen_)),
      mechanism_({info_.sign_mechanism, NULL_PTR, 0}) {
  }
 protected:
  CurveInfo info_;
  vector<CK_ATTRIBUTE_TYPE> public_attrs_;
  vector<CK_ATTRIBUTE_TYPE> private_attrs_;
  ECKeyPair keypair_;
  const int datalen_;
  unique_ptr<CK_BYTE, freer> data_;
  CK_MECHANISM mechanism_;
};

}  // namespace

#define SKIP_IF_UNIMPLEMENTED_RV(rv) \
    if ((rv) == CKR_MECHANISM_INVALID) {  \
      stringstream ss; \
      ss << "Digest type " << mechanism_type_name(mechanism_.mechanism) << " not implemented"; \
      TEST_SKIPPED(ss.str()); \
      return; \
    }

TEST_P(SignTest, SignVerify) {
  CK_RV rv = g_fns->C_SignInit(session_, &mechanism_, keypair_.private_handle());
  SKIP_IF_UNIMPLEMENTED_RV(rv);
  ASSERT_CKR_OK(rv);
  CK_BYTE output[1024];
  CK_ULONG output_len = sizeof(output);
  EXPECT_CKR_OK(g_fns->C_Sign(session_, data_.get(), datalen_, output, &output_len));

  ASSERT_CKR_OK(g_fns->C_VerifyInit(session_, &mechanism_, keypair_.public_handle()));
  EXPECT_CKR_OK(g_fns->C_Verify(session_, data_.get(), datalen_, output, output_len));
}

TEST_P(SignTest, SignFailVerifyWrong) {
  CK_RV rv = g_fns->C_SignInit(session_, &mechanism_, keypair_.private_handle());
  SKIP_IF_UNIMPLEMENTED_RV(rv);
  ASSERT_CKR_OK(rv);
  CK_BYTE output[1024];
  CK_ULONG output_len = sizeof(output);
  EXPECT_CKR_OK(g_fns->C_Sign(session_, data_.get(), datalen_, output, &output_len));

  // Corrupt one byte of the signature.
  output[0]++;

  ASSERT_CKR_OK(g_fns->C_VerifyInit(session_, &mechanism_, keypair_.public_handle()));
  EXPECT_CKR(CKR_SIGNATURE_INVALID,
             g_fns->C_Verify(session_, data_.get(), datalen_, output, output_len));
}

TEST_P(SignTest, SignFailVerifyShort) {
  CK_RV rv = g_fns->C_SignInit(session_, &mechanism_, keypair_.private_handle());
  SKIP_IF_UNIMPLEMENTED_RV(rv);
  ASSERT_CKR_OK(rv);
  CK_BYTE output[1024];
  CK_ULONG output_len = sizeof(output);
  EXPECT_CKR_OK(g_fns->C_Sign(session_, data_.get(), datalen_, output, &output_len));

  ASSERT_CKR_OK(g_fns->C_VerifyInit(session_, &mechanism_, keypair_.public_handle()));
  EXPECT_CKR(CKR_SIGNATURE_LEN_RANGE,
             g_fns->C_Verify(session_, data_.get(), datalen_, output, 4));
}

TEST_F(ReadOnlySessionTest, SignVerifyRecover) {
  vector<CK_ATTRIBUTE_TYPE> public_attrs = {CKA_VERIFY_RECOVER, CKA_ENCRYPT};
  vector<CK_ATTRIBUTE_TYPE> private_attrs = {CKA_SIGN_RECOVER, CKA_DECRYPT};
  KeyPair keypair(session_, public_attrs, private_attrs);
  const int datalen = 64;
  unique_ptr<CK_BYTE, freer> data = randmalloc(datalen);
  CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL_PTR, 0};

  CK_RV rv = g_fns->C_SignRecoverInit(session_, &mechanism, keypair.private_handle());
  if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
    TEST_SKIPPED("SignRecover not supported");
    return;
  }
  if ((rv) == CKR_MECHANISM_INVALID) {
    stringstream ss;
    ss << "Digest type " << mechanism_type_name(mechanism.mechanism) << " not implemented";
    TEST_SKIPPED(ss.str());
    return;
  }
  ASSERT_CKR_OK(rv);
  CK_BYTE output[2048];
  CK_ULONG output_len = sizeof(output);
  EXPECT_CKR_OK(g_fns->C_SignRecover(session_, data.get(), datalen, output, &output_len));
  if (g_verbose) {
    cout << "SignRecover on " << datalen << " bytes produced " << output_len << " bytes:" << endl;
    cout << "  " << hex_data(output, output_len) << endl;
  }

  CK_BYTE recovered[2048];
  CK_ULONG recovered_len = sizeof(recovered);
  ASSERT_CKR_OK(g_fns->C_VerifyRecoverInit(session_, &mechanism, keypair.public_handle()));
  ASSERT_CKR_OK(g_fns->C_VerifyRecover(session_, output, output_len, recovered, &recovered_len));
  EXPECT_EQ(datalen, recovered_len);
  EXPECT_EQ(0, memcmp(data.get(), recovered, datalen));
}

INSTANTIATE_TEST_CASE_P(Signatures, SignTest,
                        ::testing::Values("RSA",
                                          "MD5-RSA",
                                          "SHA1-RSA",
                                          "SHA256-RSA",
                                          "SHA384-RSA",
                                          "SHA512-RSA"));

TEST_P(ECSignTest, SignVerify) {
  CK_RV rv = g_fns->C_SignInit(session_, &mechanism_, keypair_.private_handle());
  SKIP_IF_UNIMPLEMENTED_RV(rv);
  ASSERT_CKR_OK(rv);
  CK_BYTE output[300];
  CK_ULONG output_len = sizeof(output);
  EXPECT_CKR_OK(g_fns->C_Sign(session_, data_.get(), datalen_, output, &output_len));

  ASSERT_CKR_OK(g_fns->C_VerifyInit(session_, &mechanism_, keypair_.public_handle()));
  EXPECT_CKR_OK(g_fns->C_Verify(session_, data_.get(), datalen_, output, output_len));
}

INSTANTIATE_TEST_CASE_P(ECSignatures, ECSignTest,
                        ::testing::Values("P-256",
                                          "P-384",
                                          "P-521",
                                          "secp256k1",
                                          "ed25519"));

}  // namespace test
}  // namespace pkcs11

