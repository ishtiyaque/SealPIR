#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"
#include <seal/seal.h>
#include <chrono>
#include <memory>
#include <random>
#include <cstdint>
#include <cstddef>

using namespace std::chrono;
using namespace std;
using namespace seal;

int main(int argc, char *argv[]) {

    uint64_t number_of_items = (96151);
    uint64_t size_per_item = 30 *  512  ; // in bytes
    uint32_t N = 4096;

    // Recommended values: (logt, d) = (12, 2) or (8, 1). 
    uint32_t logt = 30; 
    uint32_t d = 2;

    EncryptionParameters params(scheme_type::BFV);
    PirParams pir_params;

    // Generates all parameters
    cout << "Main: Generating all parameters" << endl;
    gen_params(number_of_items, size_per_item, N, logt, d, params, pir_params);

    cout << "Main: Initializing the database (this may take some time) ..." << endl;

    // Create test database
    auto db(make_unique<uint8_t[]>(number_of_items * size_per_item));

    // Copy of the database. We use this at the end to make sure we retrieved
    // the correct element.
    auto db_copy(make_unique<uint8_t[]>(number_of_items * size_per_item));

    random_device rd;
    for (uint64_t i = 0; i < number_of_items; i++) {
        for (uint64_t j = 0; j < size_per_item; j++) {
            auto val = rand() % 256;
            db.get()[(i * size_per_item) + j] = val;
            db_copy.get()[(i * size_per_item) + j] = val;
        }
    }

    // Initialize PIR Server
    cout << "Main: Initializing server and client" << endl;
    PIRServer server(params, pir_params,12);

    // Initialize PIR client....
    PIRClient client(params, pir_params);
    GaloisKeys galois_keys = client.generate_galois_keys();
    cout<<"Gal key size: "<<galois_keys.size()<<endl;

    // Set galois key for client with id 0
    cout << "Main: Setting Galois keys..."<<endl;
    server.set_galois_key(0, galois_keys);

    // Measure database setup
    auto time_pre_s = high_resolution_clock::now();
    server.set_database(move(db), number_of_items, size_per_item);
    server.preprocess_database();
    cout << "Main: database pre processed " << endl;
    auto time_pre_e = high_resolution_clock::now();
    auto time_pre_us = duration_cast<microseconds>(time_pre_e - time_pre_s).count();

    // Choose an index of an element in the DB
    uint64_t ele_index = rd() % number_of_items; // element in DB at random position
    uint64_t index = client.get_fv_index(ele_index, size_per_item);   // index of FV plaintext
    uint64_t offset = client.get_fv_offset(ele_index, size_per_item); // offset in FV plaintext
    cout << "Main: element index = " << ele_index << " from [0, " << number_of_items -1 << "]" << endl;
    cout << "Main: FV index = " << index << ", FV offset = " << offset << endl; 

    // Measure query generation
    auto time_query_s = high_resolution_clock::now();
    PirQuery query = client.generate_query(index);
    auto time_query_e = high_resolution_clock::now();
    auto time_query_us = duration_cast<microseconds>(time_query_e - time_query_s).count();
    cout << "Main: query generated" << endl;

 
    //To marshall query to send over the network, you can use serialize/deserialize:
    //std::string query_ser = serialize_query(query);
    //PirQuery query2 = deserialize_query(d, 1, query_ser, CIPHER_SIZE);

    // Measure query processing (including expansion)
    auto time_server_s = high_resolution_clock::now();
    PirReply reply = server.generate_reply(query, 0);
    auto time_server_e = high_resolution_clock::now();
    auto time_server_us = duration_cast<microseconds>(time_server_e - time_server_s).count();


    // Measure response extraction
    auto time_decode_s = chrono::high_resolution_clock::now();
    Plaintext result = client.decode_reply(reply);
    auto time_decode_e = chrono::high_resolution_clock::now();
    auto time_decode_us = duration_cast<microseconds>(time_decode_e - time_decode_s).count();

    // Convert from FV plaintext (polynomial) to database element at the client
    vector<uint8_t> elems(N * logt / 8);
    coeffs_to_bytes(logt, result, elems.data(), (N * logt) / 8);

    // Check that we retrieved the correct element
    for (uint32_t i = 0; i < size_per_item; i++) {
        if (elems[(offset * size_per_item) + i] != db_copy.get()[(ele_index * size_per_item) + i]) {
            cout << "Main: elems " << (int)elems[(offset * size_per_item) + i] << ", db "
                 << (int) db_copy.get()[(ele_index * size_per_item) + i] << endl;
            cout << "Main: PIR result wrong!" << endl;
            return -1;
        }
    }

    auto total_reply_gen_time = server.expansion_time + server.query_ntt_time + server.mult_time + 
            server.add_time + server.inter_db_construction_time + server.inter_db_ntt_time + server.inv_ntt_time;

    int query_size = 0;
    for(int i =0;i<query.size();i++) {
        query_size += query[i].size();
    }

    // Output results
    cout << "PIR result correct!" << endl;

    cout<<"\nNetwork:"<<endl;
    cout<<"\tquery size (ct): "<<query_size<<endl;
    cout<<"\tresponse size (ct): "<<reply.size()<<endl;

    cout<<"\nClient CPU:"<<endl;
    cout << "\tquery generation time (us): " << time_query_us  << endl;
    cout << "\tresponse decode time (us): " << time_decode_us  << endl;

    cout<<"\nServer CPU: "<<endl;

    cout << "\tDB pre-processing time (us): " << time_pre_us<< endl;
    cout << "\ttotal query expansion time (us): " << server.expansion_time<< endl;
    cout << "\treply generation time (blackbox): " << time_server_us<< endl;
    cout<<"\tquery ntt time (us): "<<server.query_ntt_time<<endl;
    cout<<"\tmultiplication time (us): "<<server.mult_time<<endl;
    cout<<"\tadd time (us): "<<server.add_time<<endl;
    cout<<"\tinv ntt time (us): "<<server.inv_ntt_time<<endl;
    cout<<"\tintermediate db construction time (us): "<<server.inter_db_construction_time<<endl;
    cout<<"\tintermediate db ntt time (us): "<<server.inter_db_ntt_time<<endl;
    cout<<"\tsum of components: "<<total_reply_gen_time<<endl;

    return 0;
}
