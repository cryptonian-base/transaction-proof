#ifndef ETHSNARKS_EXPORT_HPP_
#define ETHSNARKS_EXPORT_HPP_

#include "algebra/fields/bigint.hpp"
#include "algebra/curves/alt_bn128/alt_bn128_pp.hpp"       // alt_bn128_pp
#include "algebra/curves/alt_bn128/alt_bn128_init.hpp"  //alt_bn128_r_limbs
#include "algebra/curves/alt_bn128/alt_bn128_g1.hpp"    // G1
#include "algebra/curves/alt_bn128/alt_bn128_g2.hpp"    // G2

// r1cs_ppzksnark copied from ethsnark
//#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"    // r1cs_ppzksnark_proof, r1cs_ppzksnark_primary_input
#include "r1cs_gg_ppzksnark_zok.hpp"

typedef libsnark::alt_bn128_pp ppT;
typedef libsnark::alt_bn128_G1  G1T;
typedef libsnark::alt_bn128_G2  G2T;
/* //cryptonian - previous version!
typedef libsnark::r1cs_ppzksnark_proof<ppT> ProofT;
typedef libsnark::r1cs_ppzksnark_primary_input<ppT> PrimaryInputT;
typedef libsnark::r1cs_ppzksnark_verification_key<ppT> VerificationKeyT;
*/
typedef libsnark::r1cs_gg_ppzksnark_zok_proof<ppT>   ProofT;
typedef libsnark::r1cs_gg_ppzksnark_zok_primary_input<ppT> PrimaryInputT;
typedef libsnark::r1cs_gg_ppzksnark_zok_verification_key<ppT> VerificationKeyT; 

std::string HexStringFromBigint( LimbT _x);

std::string outputPointG1AffineAsHex( G1T _p );

std::string outputPointG2AffineAsHex( G2T _p );

std::string proof_to_json( ProofT &proof, PrimaryInputT &input );

std::string vk2json( VerificationKeyT &vk );

void vk2json_file( VerificationKeyT &vk, const std::string &path );


#endif
