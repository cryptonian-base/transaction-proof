using namespace libsnark;

const size_t sha256_digest_len = 256;
const size_t tree_depth = 16;
bool sha256_padding[256] = {1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0};

template<typename FieldT, typename HashT>
class basev2_gadget : public gadget<FieldT> {
public:
    
    pb_variable_array<FieldT> input_as_field_elements;
    std::shared_ptr<multipacking_gadget<FieldT> > pack_inputs;
    pb_variable_array<FieldT> input_as_bits;

    std::shared_ptr<digest_variable<FieldT> > root_digest;
    std::shared_ptr<digest_variable<FieldT> > prev_leaf_digest;
    std::shared_ptr<digest_variable<FieldT> > leaf_digest;

    std::shared_ptr<merkle_authentication_path_variable<FieldT, HashT> > path_var;
    std::shared_ptr<merkle_tree_check_read_gadget<FieldT, HashT> > ml;
    pb_variable_array<FieldT> address_bits_va;
    pb_variable<FieldT> flag;

    std::shared_ptr<block_variable<FieldT> > h_leaf_block;  // 512 bit block that constraints leaf + padding
    std::shared_ptr<sha256_compression_function_gadget<FieldT> > h_leaf_gadget; //hashing gadget for leaf

    pb_variable<FieldT> zero;
    pb_variable_array<FieldT> padding_var; /* SHA256 length padding */

    basev2_gadget(protoboard<FieldT> &pb)
    : gadget<FieldT>(pb, "basev2_gadget"){

        // set pb's primary_input_size
        {
            const size_t input_size_in_field_element = div_ceil(2 * sha256_digest_len, FieldT::capacity());
            input_as_field_elements.allocate(pb, input_size_in_field_element, "input_as_field_elements");
            this->pb.set_input_sizes(input_size_in_field_element);
        }

        prev_leaf_digest.reset(new digest_variable<FieldT>(this->pb, sha256_digest_len, "prev_leaf_digest"));
        root_digest.reset(new digest_variable<FieldT>(this->pb, sha256_digest_len, "root_digest"));
        leaf_digest.reset(new digest_variable<FieldT>(this->pb, sha256_digest_len, "leaf_digest"));

        // prev_leaf , root into input_as_bits
        input_as_bits.insert(input_as_bits.end(), prev_leaf_digest->bits.begin(), prev_leaf_digest->bits.end());
        input_as_bits.insert(input_as_bits.end(), root_digest->bits.begin(), root_digest->bits.end());

        /*
        flag is true : when packing src/target root to field, copy src root (computed root according to leaf/path)
        to target root, so when generating witness, root_digest must be called after merkle_tree_check_read_gadget.
        otherwise root_digest will be overwrite by ml, In this case, given a wrong root, it will pass.
        flag is false : don't do above. so when generating witness, root_digest must be called before merkle_tree_check_read_gadget.
        otherwise, when calling ml generate_r1cs_witness, it will be packing empty/wrong target root, causing packed_source and
        packed_target not equal, it will not pass. 
        */
        flag.allocate(this->pb, "flag");
        address_bits_va.allocate(this->pb, tree_depth, "address_bits");
        zero.allocate(this->pb, "zero");
        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);
        
        pack_inputs.reset(new multipacking_gadget<FieldT>(this->pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " pack_inputs")));

        path_var.reset(new merkle_authentication_path_variable<FieldT, HashT>(this->pb, tree_depth, "path_var"));
        ml.reset(new merkle_tree_check_read_gadget<FieldT, HashT>(this->pb, tree_depth, address_bits_va, *leaf_digest,
        *root_digest, *path_var, flag, "ml"));

        for (size_t i = 0; i < 256; ++i) {
            if (sha256_padding[i])
                padding_var.emplace_back(ONE);
            else
                padding_var.emplace_back(zero);
        }

        h_leaf_block.reset(new block_variable<FieldT> (this->pb, {leaf_digest->bits,
          padding_var}, "h_leaf_block"
        ));
        h_leaf_gadget.reset(new sha256_compression_function_gadget<FieldT>(this->pb, IV,
        h_leaf_block->bits, *prev_leaf_digest, "h_leaf_gadget"));
    }

    void generate_r1cs_constraints()
    {
        pack_inputs->generate_r1cs_constraints(true);

        h_leaf_gadget->generate_r1cs_constraints();
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");
        path_var->generate_r1cs_constraints();
        ml->generate_r1cs_constraints();
    }
    void generate_r1cs_witness(const bit_vector &prev_leaf, const bit_vector &leaf,
                              const bit_vector &root, const size_t address,
                              const bit_vector &address_bits, const std::vector<merkle_authentication_node> &path)
    {
        this->pb.val(flag) = FieldT::one();
        this->pb.val(zero) = FieldT::zero();
        prev_leaf_digest->generate_r1cs_witness(prev_leaf);
        leaf_digest->generate_r1cs_witness(leaf);
        h_leaf_gadget->generate_r1cs_witness();
        root_digest->generate_r1cs_witness(root);
        
        pack_inputs->generate_r1cs_witness_from_bits();
        leaf_digest->generate_r1cs_witness(leaf);
        address_bits_va.fill_with_bits(this->pb, address_bits);
        path_var->generate_r1cs_witness(address, path);
        ml->generate_r1cs_witness();

        //make sure that read checker didn't accidentally overwrite anything

        address_bits_va.fill_with_bits(this->pb, address_bits);
        leaf_digest->generate_r1cs_witness(leaf);
        root_digest->generate_r1cs_witness(root);
    }
};

template<typename FieldT>
r1cs_primary_input<FieldT> l_input_map(const bit_vector &h1,
                                             const bit_vector &h2
                                            )
{
    // Construct the multipacked field points which encode the verifier's knowledge. 
    // This is the "dual" of the multipacking gadget logic in the constructor.
    assert(h1.size() == sha256_digest_len);
    assert(h2.size() == sha256_digest_len);

    bit_vector input_as_bits;
    input_as_bits.insert(input_as_bits.end(), h1.begin(), h1.end());
    input_as_bits.insert(input_as_bits.end(), h2.begin(), h2.end());
    std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
    return input_as_field_elements;
}
