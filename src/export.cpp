// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <fstream>
#include <iostream>
#include <cassert>
#include <iomanip>

#include "export.hpp"

std::string HexStringFromBigint(libsnark::bigint<libsnark::alt_bn128_r_limbs> _x){
    
    mpz_t value;
    ::mpz_init(value);

    _x.to_mpz(value);
    char *value_out_hex = mpz_get_str(nullptr, 16, value);

    std::string str(value_out_hex);

    ::mpz_clear(value);
    ::free(value_out_hex);

    return str;
}


std::string outputPointG1AffineAsHex(G1T _p)
{
        auto aff = _p;
        aff.to_affine_coordinates();
        return "\"0x" +  HexStringFromBigint(aff.X.as_bigint()) + "\", \"0x" + HexStringFromBigint(aff.Y.as_bigint()) + "\""; 
}


std::string outputPointG2AffineAsHex(G2T _p)
{
        G2T aff = _p;

        if (aff.Z.c0.as_bigint() != "0" && aff.Z.c1.as_bigint() != "0" ) {
            aff.to_affine_coordinates();
        }
        return "[\"0x" +
                HexStringFromBigint(aff.X.c1.as_bigint()) + "\", \"0x" +
                HexStringFromBigint(aff.X.c0.as_bigint()) + "\"],\n [\"0x" + 
                HexStringFromBigint(aff.Y.c1.as_bigint()) + "\", \"0x" +
                HexStringFromBigint(aff.Y.c0.as_bigint()) + "\"]"; 
}

//typedef libsnark::r1cs_ppzksnark_proof<ppT> ProofT;
//std::string outputPointG1AffineAsHex(G1T _p)
//typedef libsnark::alt_bn128_G1  G1T;
std::string proof_to_json(ProofT &proof, PrimaryInputT &input) {
    std::stringstream ss;
    ss << "{\n";
    // Cryptonian - 'Problem' 
    // : no suitable user-defined conversion from "libsnark::knowledge_commitment<libsnark::G1<ppT>, libsnark::G1<ppT>>" to "G1T" exists
    // 그렇다면 knowledge_commitment 의 'g,h' 등은 어떤 의미를 지니나??
    // algebra/knowledge_commitment/knowledge_commitment.hpp 확인 필요!!
    // Last Update : r1cs_gg_ppzksnark_zok.hpp를 복사해왔다!!.. 다시 rebase!!

    ss << " \"A\" :[" << outputPointG1AffineAsHex(proof.g_A) << "],\n";
    ss << " \"B\"  :[" << outputPointG2AffineAsHex(proof.g_B)<< "],\n";
    ss << " \"C\"  :[" << outputPointG1AffineAsHex(proof.g_C)<< "],\n";
    ss << " \"input\" :" << "["; //1 should always be the first variavle passed

    for (size_t i = 0; i < input.size(); ++i)
    {   
        ss << "\"0x" << HexStringFromBigint(input[i].as_bigint()) << "\""; 
        if ( i < input.size() - 1 ) { 
            ss<< ", ";
        }
    }
    ss << "]\n";
    ss << "}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);

    return(ss.str());
}


std::string vk2json(VerificationKeyT &vk )
{
    std::stringstream ss;
    // 참고 : libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp
    // 기존 miximus : r1cs_gg_ppzksnark_zok/r1cs_gg_ppzksnark_zok.hpp
    // Last Update : r1cs_gg_ppzksnark_zok.hpp를 복사해왔다!!.. 다시 rebase!!

    unsigned icLength = vk.gamma_ABC_g1.rest.indices.size() + 1;
    //unsigned icLength = vk.encoded_IC_query.rest.indices.size() + 1;

    ss << "{\n";
    ss << " \"alpha\" :[" << outputPointG1AffineAsHex(vk.alpha_g1) << "],\n";  // org : alpha_g1
    ss << " \"beta\"  :[" << outputPointG2AffineAsHex(vk.beta_g2) << "],\n";    // org : beta_g2
    ss << " \"gamma\" :[" << outputPointG2AffineAsHex(vk.gamma_g2) << "],\n";
    ss << " \"delta\" :[" << outputPointG2AffineAsHex(vk.delta_g2)<< "],\n";

    ss <<  "\"gammaABC\" :[[" << outputPointG1AffineAsHex(vk.gamma_ABC_g1.first) << "]";
    
    for (size_t i = 1; i < icLength; ++i)
    {   
        auto vkICi = outputPointG1AffineAsHex(vk.gamma_ABC_g1.rest.values[i - 1]);
        ss << ",[" <<  vkICi << "]";
    } 
    ss << "]";
    ss << "}";
    return ss.str();
}


void vk2json_file(VerificationKeyT &vk, const std::string &path )
{
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    fh << vk2json(vk);
    fh.flush();
    fh.close();
}

