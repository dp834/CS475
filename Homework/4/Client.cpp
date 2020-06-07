#include "ASSIGNMENT4.hpp"

using boost::asio::ip::tcp;


/* used when receiving arbitrarily sized messages and copies string from buffer to a string object */
void store_recv_msg(std::istream& recv_buf, std::string& msg_buf){
        /* read everything from the buffer until the MSG_END sequence */
        msg_buf.resize(0);
        char c, p;
        recv_buf.read(&p, 1);
        while(recv_buf){
            recv_buf.read(&c, 1);
            /* read until the MSG_END is read */
            if(p == '\13' && c == '\10'){
                break;
            }
            msg_buf += p;
            p = c;
        }
}

int main(int argc, char* argv[]){
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
        if(argc != 4){
            std::cerr << "Usage: client <host> <username> <rsa-keys-dir>" << std::endl;
            return 1;
        }

        /* Read all the rsa keys that are needed */
        std::string rsa_key_dir = argv[3];
        std::string fname = rsa_key_dir + "/private.pem";
        FILE *file = fopen(fname.c_str(), "rb");
        if(file){
            rsa_client_private = RSA_new();
            rsa_client_private = PEM_read_RSAPrivateKey(file, &rsa_client_private, NULL,NULL);
        }else{
            std::cerr << "Error opening client private key" << std::endl;
            return -1;
        }

        fname = rsa_key_dir + "/public.pem";
        file = fopen(fname.c_str(), "rb");
        if(file){
            rsa_client_public = RSA_new();
            rsa_client_public = PEM_read_RSA_PUBKEY(file, &rsa_client_public, NULL,NULL);
        }else{
            std::cerr << "Error opening client private key" << std::endl;
            return -1;
        }

        fname = rsa_key_dir + "/server.pem";
        file = fopen(fname.c_str(), "rb");
        if(file){
            rsa_server_public = RSA_new();
            rsa_server_public = PEM_read_RSA_PUBKEY(file, &rsa_server_public, NULL,NULL);
        }else{
            std::cerr << "Error opening server public key" << std::endl;
            return -1;
        }



        // required for all boost asio operations
        boost::asio::io_service io;

        /* Attempt to make a connection with the server */
        tcp::resolver resolver(io);
        tcp::resolver::query query(argv[1], PORT_STR);
        tcp::resolver::iterator endpoint_iter = resolver.resolve(query);

        tcp::socket socket(io);
        boost::asio::connect(socket, endpoint_iter);
        /* If no error was thrown we can continue */

        /* Start by encrypting the supplied username with the server's public key */
        if((len = RSA_public_encrypt(strlen(argv[2]),(unsigned char*)argv[2], tmp_buf, rsa_server_public, RSA_PKCS1_PADDING)) < 0){
            ERR_error_string(ERR_get_error(), (char *)tmp_buf);
            std::cerr << "Error encrypting username: " << tmp_buf << std::endl;
            /* TODO: find error code or something */
            socket.close();
            return -1;
        }

        /* Marks end of first challenge for the server */
        tmp_buf[len++] = '\13';
        tmp_buf[len++] = '\10';

        /* Inital challenge, send username encrypted with server's public key */
        len = boost::asio::write(socket, boost::asio::buffer(tmp_buf, len), boost::asio::transfer_exactly(len));

        /* Server should respond with '<username><aed-key>'
         * decrypted with server's private key and encypted
         * with client's public key
         * Response should end with the MSG_END string
         */
        len = boost::asio::read_until(socket, read_buf, MSG_END);

        /* move from the streambuffer into the string object */
        store_recv_msg(to_recv, buf);

        /* decrypt the message using the server's public key*/
        if((len = RSA_public_decrypt(buf.length(),(unsigned char*)buf.c_str(), tmp_buf, rsa_server_public, RSA_NO_PADDING)) < 0){
            ERR_error_string(ERR_get_error(), (char *)tmp_buf);
            std::cerr << "Error decrypting with server public: " << tmp_buf << std::endl;
            socket.close();
            return -1;
        }

        /* decrypt the mesage using the client's private key */
        if((len = RSA_private_decrypt(len, tmp_buf, tmp, rsa_client_private, RSA_PKCS1_PADDING)) < 0){
            ERR_error_string(ERR_get_error(), (char *)tmp_buf);
            std::cerr << "Error decrypting with client private: " << tmp_buf << std::endl;
            socket.close();
            return -1;
        }

        /* Check that the response begins with the username we sent, if not then close */
        if(strncmp(argv[2], (char*)tmp, strlen(argv[2])) != 0){
            std::cerr << "Server did not respond with username" << std::endl;
            /* server responded improperly, bad communication? */
            socket.close();
            return -1;
        }

        /* I know that this looks awful, but I ran into more issues than I expected
         * as i have never used boost or openssl.
         * Hence the code is kinda just thrown together, I intend on cleaning this up
         * in the future as I think it would make for a great learning experience */
        /* All the parameters for aes encryption */
        unsigned char aes_key[256/8];
        unsigned char aes_iv[AES_BLOCK_SIZE];
        AES_KEY *aes_enc, *aes_dec;
        /* Copy from the recieve buffer starting after the username and copy to the length of the aes_key */
        memcpy(aes_key, &tmp[strlen(argv[2])], sizeof(aes_key));
        /* I'm not sure why I need a aes context for encryption and decryption to be separate,
         * but that's what all the documentation/tutorials i saw did */
        aes_enc = new AES_KEY();
        aes_dec = new AES_KEY();
        AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, aes_enc);
        AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, aes_dec);

        unsigned char aes_data_plain[1024];
        unsigned char aes_data_enc[1024];


        /* The way I am sending encrypted data back and forth is as follows
         * <iv><encrypted-data>
         * the length of iv is AES_BLOCK_SIZE
         * the length of the data is 1024 */

        /* create a random initialization vector 
         * This is here due to the fencepost problem and poor structure
         */

        RAND_bytes(aes_iv, sizeof(aes_iv));
        len = boost::asio::write(socket, boost::asio::buffer(aes_iv, len), boost::asio::transfer_exactly(sizeof(aes_iv)));
        /* clear everything just to be safe */
        memset(aes_data_plain, 0, sizeof(aes_data_plain));
        memset(aes_data_enc, 0, sizeof(aes_data_enc));

        /* this loop just sends data over the socket then waits for a response and prints it out.*/
        while(!std::cin.eof()){
            int i;
            /* don't fill up a message larger than the buffer */
            for(i = 0; i < sizeof(aes_data_plain)-1; i++){
                /* if stdin is eof then send what's left and exit */
                if(std::cin.eof()){
                    break;
                }
                /* read until newline */
                if((aes_data_plain[i] = std::cin.get()) == '\n'){
                    /* replace newline with end of string */
                    aes_data_plain[i] = '\0';
                    break;
                }
            }
            /* if nothing is sent then restart */
            if(i < 1){
                continue;
            }
            /* mark the end of the string, due to for loop condition
             * we don't have to worry about bounds for the buffer */
            aes_data_plain[i+1] = '\0';

            /* Encrypt the plaintext data */
            AES_cbc_encrypt(aes_data_plain, aes_data_enc, sizeof(aes_data_plain), aes_enc, aes_iv, AES_ENCRYPT);
            /* Send the plaintext data */
            len = boost::asio::write(socket, 
                                    boost::asio::buffer(aes_data_enc, sizeof(aes_data_enc)),
                                    boost::asio::transfer_exactly(sizeof(aes_data_enc)));

            /* Read the new IV from the server */
            len = boost::asio::read(socket,
                                    boost::asio::buffer(aes_iv, sizeof(aes_iv)),
                                    boost::asio::transfer_exactly(sizeof(aes_iv)));

            /* Read the encrypted response from the server */
            len = boost::asio::read(socket,
                                    boost::asio::buffer(aes_data_enc, sizeof(aes_data_enc)),
                                    boost::asio::transfer_exactly(sizeof(aes_data_enc)));

            /* Decrypt what the server sent using their iv */
            AES_cbc_encrypt(aes_data_enc, aes_data_plain, sizeof(aes_data_plain), aes_dec, aes_iv, AES_DECRYPT);

            /* Print out what the server responded with */
            std::cout << "Recieved: " <<  aes_data_plain << std::endl;

            /* generate new iv and send it again */
            RAND_bytes(aes_iv, sizeof(aes_iv));
            len = boost::asio::write(socket, boost::asio::buffer(aes_iv, len), boost::asio::transfer_exactly(sizeof(aes_iv)));

            /* clear everything just to be safe */
            memset(aes_data_plain, 0, sizeof(aes_data_plain));
            memset(aes_data_enc, 0, sizeof(aes_data_enc));
        }

        /* Once sdtin reaches eof close cleanly */
        socket.close();

    }catch (std::exception& e){
        /* if something goes wrong show what it is */
        std::cerr << e.what() << std::endl;
        store_recv_msg(to_recv, buf);
        std::cerr << "Error: '" << buf << "'" << std::endl;
    }

    return 0;
}

