#include "ASSIGNMENT4.hpp"
// Symmetric
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
// Public key
#include <boost/array.hpp>
#include <boost/asio.hpp>

#include <iostream>
#include <string>

#include <fstream>

using boost::asio::ip::tcp;


void store_recv_msg(std::istream& recv_buf, std::string& msg_buf){
        /* read everything from the buffer until the MSG_END sequence */
        msg_buf.resize(0);
        char c, p;
        recv_buf.read(&p, 1);
        while(recv_buf){
            recv_buf.read(&c, 1);
            if(p == '\13' && c == '\10'){
                break;
            }
            msg_buf += p;
            p = c;
        }
}

int main(int argc, char* argv[]){
    std::string key("");
    boost::asio::streambuf read_buf;
    boost::asio::streambuf write_buf;
    std::ostream to_send(&write_buf);
    std::istream to_recv(&read_buf);
    std::string buf("");
    unsigned char tmp_buf[4096];
    unsigned char tmp[4096];
    //Crypto crypto("../client/", "../server/");
    RSA *rsa_client_public;
    RSA *rsa_client_private;
    RSA *rsa_server_public;
    int len;

    try{
        if(argc != 3){
            std::cerr << "Usage: client <host> <username>" << std::endl;
            return 1;
        }


        std::string fname = "../client/private.pem";
        FILE *file = fopen(fname.c_str(), "rb");
        if(file){
            rsa_client_private = RSA_new();
            rsa_client_private = PEM_read_RSAPrivateKey(file, &rsa_client_private, NULL,NULL);
        }else{
            std::cerr << "Error opening client private key" << std::endl;
            throw 20;
        }

        fname = "../client/public.pem";
        file = fopen(fname.c_str(), "rb");
        if(file){
            rsa_client_public = RSA_new();
            rsa_client_public = PEM_read_RSA_PUBKEY(file, &rsa_client_public, NULL,NULL);
        }else{
            std::cerr << "Error opening client private key" << std::endl;
            throw 20;
        }

        fname = "../client/server.pem";
        file = fopen(fname.c_str(), "rb");
        if(file){
            rsa_server_public = RSA_new();
            rsa_server_public = PEM_read_RSA_PUBKEY(file, &rsa_server_public, NULL,NULL);
        }else{
            std::cerr << "Error opening server public key" << std::endl;
            throw 20;
        }



        // required for all boost asio operations
        boost::asio::io_service io;

        tcp::resolver resolver(io);
        tcp::resolver::query query(argv[1], PORT_STR);
        tcp::resolver::iterator endpoint_iter = resolver.resolve(query);

        tcp::socket socket(io);
        boost::asio::connect(socket, endpoint_iter);


        if((len = RSA_public_encrypt(strlen(argv[2]),(unsigned char*)argv[2], tmp_buf, rsa_server_public, RSA_PKCS1_PADDING)) < 0){
            ERR_error_string(ERR_get_error(), (char *)tmp_buf);
            std::cerr << "Error encrypting username: " << tmp_buf << std::endl;
            /* TODO: find error code or something */
            socket.close();
            throw 20;
        }


        std::cout << "Sent: '" << argv[2] << "'" << std::endl;
        /* Marks end of first challenge for the server */

        tmp_buf[len] = '\13';
        tmp_buf[len+1] = '\10';
        len +=2;
        /* Inital challenge, send username encrypted with server's public key */
        len = boost::asio::write(socket, boost::asio::buffer(tmp_buf, len), boost::asio::transfer_exactly(len));
        std::cout << "Sent: " << len << " bytes" << std::endl;

        /* Server should respond with '<username><aed-key><iv>'
         * decrypted with server's private key and encypted
         * with client's public key
         * Response should end with the MSG_END string
         */
        len = boost::asio::read_until(socket, read_buf, MSG_END);

        store_recv_msg(to_recv, buf);
        std::cout << buf.length() << " : " << len << std::endl;

        std::cout << "username and aes key encrypted: ";
        std::cout.write((char*)buf.c_str(), len);
        std::cout << std::endl;

        if((len = RSA_public_decrypt(buf.length(),(unsigned char*)buf.c_str(), tmp_buf, rsa_server_public, RSA_NO_PADDING)) < 0){
            ERR_error_string(ERR_get_error(), (char *)tmp_buf);
            std::cerr << "Error decrypting with server public: " << tmp_buf << std::endl;
            /* TODO: find error code or something */
            socket.close();
            throw 20;
        }

        std::cout << len << " : "  << buf.length() << " : " <<  RSA_size(rsa_server_public) << " : " << sizeof(tmp_buf) << std::endl;

        if((len = RSA_private_decrypt(len, tmp_buf, tmp, rsa_client_private, RSA_PKCS1_PADDING)) < 0){
            ERR_error_string(ERR_get_error(), (char *)tmp_buf);
            std::cerr << "Error decrypting with client private: " << tmp_buf << std::endl;
            /* TODO: find error code or something */
            socket.close();
            throw 20;
        }

        std::cout << len << " username and aes key :";
        std::cout.write((char*)tmp, len);
        std::cout << std::endl;

        buf = (char *) tmp;
        if(strncmp(argv[2], (char*)tmp, strlen(argv[2])) != 0){
            /* server responded improperly, bad communication? */
            socket.close();
            throw 20;
        }
        unsigned char aes_key[256/8];
        unsigned char aes_iv[AES_BLOCK_SIZE];
        AES_KEY *aes_enc, *aes_dec;
        memcpy(aes_key, &tmp[strlen(argv[2])], sizeof(aes_key));
        aes_enc = new AES_KEY();
        aes_dec = new AES_KEY();
        AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, aes_enc);
        AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, aes_dec);

        std::cout << "aes key: ";
        std::cout.write((char*)aes_key, sizeof(aes_key));
        std::cout << std::endl;

        unsigned char aes_data_plain[1024];
        unsigned char aes_data_enc[1024];
        int i;
        RAND_bytes(aes_iv, sizeof(aes_iv));
        /* start with aes_iv, than spit out the aes encrypted data */
        std::cout << "Sending iv" << std::endl;
        len = boost::asio::write(socket, boost::asio::buffer(aes_iv, len), boost::asio::transfer_exactly(sizeof(aes_iv)));
        std::cout << "Sent iv" << std::endl;
        while(!std::cin.eof()){
            memset(aes_data_plain, 0, sizeof(aes_data_plain));
            memset(aes_data_enc, 0, sizeof(aes_data_enc));
            for(i = 0; i < sizeof(aes_data_plain)-1; i++){
                if(std::cin.eof()){
                    break;
                }
                if((aes_data_plain[i] = std::cin.get()) == '\n'){
                    break;
                }
            }
            if(i < 1){
                continue;
            }
            aes_data_plain[i+1] = '\0';

            std::cout << "Plain text (" << i << "): " << aes_data_plain << std::endl;

            AES_cbc_encrypt(aes_data_plain, aes_data_enc, sizeof(aes_data_plain), aes_enc, aes_iv, AES_ENCRYPT);

            len = boost::asio::write(socket, boost::asio::buffer(aes_data_enc, sizeof(aes_data_enc)), boost::asio::transfer_exactly(sizeof(aes_data_enc)));

            std::cout << "Sent enc: " << len << " : " << sizeof(aes_data_enc) << std::endl;

            len = boost::asio::read(socket, boost::asio::buffer(aes_iv, sizeof(aes_iv)), boost::asio::transfer_exactly(sizeof(aes_iv)));
            std::cout << "Read iv: " << len << " : " << sizeof(aes_iv) << std::endl;
            len = boost::asio::read(socket, boost::asio::buffer(aes_data_enc, sizeof(aes_data_enc)), boost::asio::transfer_exactly(sizeof(aes_data_enc)));
            std::cout << "Read enc: " << len << " : " << sizeof(aes_data_enc) << std::endl;
            memset(aes_data_plain, 0 , sizeof(aes_data_plain));
            AES_cbc_encrypt(aes_data_enc, aes_data_plain, sizeof(aes_data_plain), aes_dec, aes_iv, AES_DECRYPT);

            std::cout << "Recieved: " <<  aes_data_plain << std::endl;
            RAND_bytes(aes_iv, sizeof(aes_iv));
            /* start with aes_iv, than spit out the aes encrypted data */
            std::cout << "Sending iv" << std::endl;
            len = boost::asio::write(socket, boost::asio::buffer(aes_iv, len), boost::asio::transfer_exactly(sizeof(aes_iv)));
            std::cout << "Sent iv" << std::endl;
        }



        socket.close();

    }catch (std::exception& e){
        std::cerr << e.what() << std::endl;
        store_recv_msg(to_recv, buf);
        std::cout << "Error: '" << buf << "'" << std::endl;
    }

    return 0;
}


