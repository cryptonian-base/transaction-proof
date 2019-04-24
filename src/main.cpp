#include <ctime>
#include <cstdlib>
#include "snark.hpp"
#include <sys/time.h>
#include <iostream> // cerr
#include <fstream>  // ofstream

#include <iterator>

// cryptonian
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include <boost/optional/optional_io.hpp>

using namespace libsnark;
using namespace std;

//=== cryptonian ===//
void writeFileBytes(const char* filename, std::vector<bool>& fileBytes){
    std::ofstream file(filename, std::ios::out|std::ios::binary);
    std::copy(fileBytes.cbegin(), fileBytes.cend(),
        std::ostream_iterator<bool>(file));
    
    file.flush();
}

std::vector<bool> readFileBytes(const char* filename)
{
    std::ifstream file(filename, std::ifstream::binary);
    vector<bool> out_ve;
    
    file.seekg(0, std::ios::beg);
    char ch;
    while(file.good()) {

        file >> ch;
        if (file.eof()) break;
        switch(ch) {
            case '0' :
                out_ve.push_back(false);
                break;
            case '1' :
                out_ve.push_back(true);
                break;
            default :
                break;
        }
    }

    return out_ve;
}


//==========================//


int stub_main_verify()//( const char *prog_name, int argc, const char **argv )
{
    /*
    if( argc < 3 )
    {
        std::cerr << "Usage: " << prog_name << " " << argv[0] << " <vk.json> <proof.json>" << std::endl;
        return 1;
    }
    */
    auto vk_file = "vk.raw";//argv[1];
    auto proof_file = "proof.raw";//argv[2];

    // Read verifying key file
    std::stringstream vk_stream;
    std::ifstream vk_input(vk_file);
    if( ! vk_input ) {
        std::cerr << "Error: cannot open " << vk_file << std::endl;
        return 2;
    }
    vk_stream << vk_input.rdbuf();
    vk_input.close();

    // Read proof file
    std::stringstream proof_stream;
    std::ifstream proof_input(proof_file);
    if( ! proof_input ) {
        std::cerr << "Error: cannot open " << proof_file << std::endl;
        return 2;
    }
    proof_stream << proof_input.rdbuf();
    proof_input.close();

    int status=0;
    //r1cs_ppzksnark.hpp 에 있는 r1cs_ppzksnark_verification_key, r1cs_ppzksnark_proof 타입에 맞게 읽어야함... ㅠㅠ
    //status = verify_proof<default_r1cs_ppzksnark_pp>(keypair.vk, *proof, prev_leaf, root);

    bit_vector prev_leaf =  readFileBytes("prev_leaf.public");
    bit_vector root = readFileBytes("root.public");

 
//=== cryptonian - iostream from VerifyingKey and Proof ====//
    ifstream fin_proof("proof.stream");
    r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof;
    // proof >> fin_proof;
    fin_proof >> proof;
    fin_proof.close();

    r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vk ;
    ifstream fin_vk ("vk.stream");
    // vk >> fin_vk;
    fin_vk >> vk;
    fin_vk.close();

    status = verify_proof<default_r1cs_ppzksnark_pp>(vk, proof, prev_leaf, root);
//===========================================================//

    return status;
}
int main( int argc, char **argv )
{
    if( argc < 2 )
    {
        cerr << "Usage: " << argv[0] << " <prove|verify> [...]" << endl;
        return 1;
    }

    const std::string arg_cmd(argv[1]);

    default_r1cs_ppzksnark_pp::init_public_params();
    typedef Fr<default_r1cs_ppzksnark_pp> FieldT;
    auto keypair = generate_keypair<default_r1cs_ppzksnark_pp, sha256_two_to_one_hash_gadget<FieldT> >();
    bit_vector leaf = int_list_to_bits({183, 231, 178, 111, 197, 66, 169, 241, 210, 48, 239, 205, 118, 75, 152, 233, 23, 244, 68, 121, 155, 134, 181, 131, 32, 157, 253, 177, 49, 186, 62, 132}, 8);
    bit_vector prev_leaf = int_list_to_bits({78, 144, 206, 42, 80, 100, 176, 75, 200, 232, 113, 98, 19, 218, 162, 124, 58, 186, 16, 209, 143, 237, 155, 247, 76, 51, 189, 234, 207, 145, 110, 196}, 8);
    std::vector<merkle_authentication_node> path;

    //=== cryptonian - iostream from VerifyingKey and Proof ====//
    ofstream fout_vk("vk.stream");
    fout_vk << keypair.vk;
    fout_vk.close();
    //==========================================================//


    bit_vector prev_hash = leaf;
    bit_vector root;
    bit_vector address_bits;
    size_t address = 0;
    generate_merkle_and_branch<sha256_two_to_one_hash_gadget<Fr<default_r1cs_ppzksnark_pp> > > (prev_leaf, leaf, root, address, address_bits, path);

    //writeFileBytes(const char* filename, std::vector<bool>& fileBytes)
    writeFileBytes("root.public", root);
    writeFileBytes("prev_leaf.public", prev_hash);

    struct timeval start, end;
    //boost::optional<r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp>> proof = boost::none;

    if( arg_cmd == "prove" )
    {
        cout << "generating proof...." << endl;
        gettimeofday(&start, NULL);
        auto proof = generate_proof<default_r1cs_ppzksnark_pp, sha256_two_to_one_hash_gadget<FieldT> >(keypair.pk, prev_leaf, leaf, root, address, address_bits, path);
        gettimeofday(&end, NULL);
        cout << "Proof generated!" << endl;
        cout << "take time : " << (end.tv_sec - start.tv_sec) << " second " << (end.tv_usec - start.tv_usec) <<  " microseconds" << endl;
        //return main_prove(argc, argv);

        //=== cryptonian - iostream from VerifyingKey and Proof ====//
        ofstream fout_proof("proof.stream");
        fout_proof << proof ;
        fout_proof.close();
        //==========================================================//
    }
    else if( arg_cmd == "verify" )
    {
        cout << "verifying proof...." << endl;
        gettimeofday(&start, NULL);
        assert(stub_main_verify());
        gettimeofday(&end, NULL);
        cout << "verify proof finish!" << endl;
        cout << "take time : " << (end.tv_sec - start.tv_sec) << " second " << (end.tv_usec - start.tv_usec) <<  " microseconds" << endl;
        //return stub_main_verify(argv[0], argc-1, (const char **)&argv[1]);
    }

    //cerr << "Error: unknown sub-command " << arg_cmd << endl;
    return 0;
}
#if 0
int main(void) {
    default_r1cs_ppzksnark_pp::init_public_params();
    typedef Fr<default_r1cs_ppzksnark_pp> FieldT;
    auto keypair = generate_keypair<default_r1cs_ppzksnark_pp, sha256_two_to_one_hash_gadget<FieldT> >();

    bit_vector leaf = int_list_to_bits({183, 231, 178, 111, 197, 66, 169, 241, 210, 48, 239, 205, 118, 75, 152, 233, 23, 244, 68, 121, 155, 134, 181, 131, 32, 157, 253, 177, 49, 186, 62, 132}, 8);
    bit_vector prev_leaf = int_list_to_bits({78, 144, 206, 42, 80, 100, 176, 75, 200, 232, 113, 98, 19, 218, 162, 124, 58, 186, 16, 209, 143, 237, 155, 247, 76, 51, 189, 234, 207, 145, 110, 196}, 8);
    std::vector<merkle_authentication_node> path;

    bit_vector prev_hash = leaf;
    bit_vector root;
    bit_vector address_bits;
    size_t address = 0;

    generate_merkle_and_branch<sha256_two_to_one_hash_gadget<Fr<default_r1cs_ppzksnark_pp> > > (prev_leaf, leaf, root, address, address_bits, path);

    cout << "generating proof...." << endl;
    struct timeval start, end;
    gettimeofday(&start, NULL);
    auto proof = generate_proof<default_r1cs_ppzksnark_pp, sha256_two_to_one_hash_gadget<FieldT> >(keypair.pk, prev_leaf, leaf, root, address, address_bits, path);
    gettimeofday(&end, NULL);
    cout << "Proof generated!" << endl;
    cout << "take time : " << (end.tv_sec - start.tv_sec) << " second " << (end.tv_usec - start.tv_usec) <<  " microseconds" << endl;

    assert(verify_proof<default_r1cs_ppzksnark_pp>(keypair.vk, *proof, prev_leaf, root));
    gettimeofday(&start, NULL);

    cout << "verify proof finish!" << endl;
    cout << "take time : " << (start.tv_sec - end.tv_sec) << " second " << (start.tv_usec - end.tv_usec) << " microseconds" << endl;

    return 0;
}
#endif
