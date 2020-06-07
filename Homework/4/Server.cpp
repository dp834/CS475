// Just used to hold the port and any other configurable information between the client and server
#include "ASSIGNMENT4.hpp"

// Symmetric
#include <openssl/aes.h>
// Public key
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// Library for wrapping c functions in a c++ manner
// Using it as an opportunity to learn how to as it's common in the industry for c++
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/process/child.hpp>
#include <boost/process.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <string>
#include <iostream>

using boost::asio::ip::tcp;

// TCP_Connection extends enable shared from this
// This makes TCP_Connection stay alive as long as something
// still has a reference to it
class TCP_Connection
    :public boost::enable_shared_from_this<TCP_Connection>
{
/*TODO: add timeout if nothing is sent from client */
public:
    typedef boost::shared_ptr<TCP_Connection> pointer;

    static pointer create(boost::asio::io_service& io, std::string rsa_dir)
    {
        return pointer(new TCP_Connection(io, rsa_dir));
    }

    tcp::socket& socket()
    {
        return socket_;
    }

    void start()
    {
        /* wait for the client to send it's challenge message*/
        boost::asio::async_read_until(socket_, read_buf, MSG_END,
            boost::bind(&TCP_Connection::challenge_client, shared_from_this(),
                boost::asio::placeholders::error,
                boost::asio::placeholders::bytes_transferred));
    }

private:
    TCP_Connection(boost::asio::io_service& io, std::string rsa_dir)
        : socket_(io),
          to_send(&write_buf),
          to_recv(&read_buf),
          rsa_dir(rsa_dir)
    {

        std::string fname = rsa_dir + "private.pem";
        FILE *file = fopen(fname.c_str(), "rb");
        if(file){
            rsa_server_private = RSA_new();
            rsa_server_private = PEM_read_RSAPrivateKey(file, &rsa_server_private, NULL,NULL);
        }else{
            std::cerr << "Error opening server private key" << std::endl;
            stop();
        }

        fname = rsa_dir + "public.pem";
        file = fopen(fname.c_str(), "rb");
        if(file){
            rsa_server_public = RSA_new();
            rsa_server_public = PEM_read_RSA_PUBKEY(file, &rsa_server_public, NULL,NULL);
        }else{
            std::cerr << "Error opening server public key" << std::endl;
            stop();
        }

        memset(tmp_msg_buf, 0, sizeof(tmp_msg_buf));
    }

    void load_client_public_key(){
        std::string fname = rsa_dir + username + ".pem";
        FILE *file = fopen(fname.c_str(), "rb");
        if(file){
            rsa_client_public = RSA_new();
            rsa_client_public = PEM_read_RSA_PUBKEY(file, &rsa_client_public, NULL,NULL);
        }else{
            std::cerr << "Error opening " << username << "'s public key" << std::endl;
            stop();
        }
    }

    void initialize_aes_parameters(){
        RAND_bytes(aes_key, sizeof(aes_key));
        aes_enc = new AES_KEY();
        aes_dec = new AES_KEY();
        AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, aes_enc);
        AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, aes_dec);
    }

    /* how we can terminate a session */
    void stop()
    {
        if(username.size()){
            std::cout << "Closing connection with: " << username << std::endl;
        }else{
            std::cout << "Closing connection with unconnected user" << std::endl;
        }

        // check why these crash the program
        /*if(rsa_server_private){
            RSA_free(rsa_server_private);
        }
        if(rsa_server_public){
            RSA_free(rsa_server_public);
        }
        if(rsa_client_public){
            RSA_free(rsa_client_public);
        }*/
    }

    void challenge_client(const boost::system::error_code& error,
        size_t bytes_transferred)
    {
        if(error){
            std::cout << "Error" << std::endl;
            throw boost::system::system_error(error);
        }
        if(bytes_transferred < 0){
            /* Find some error to throw*/
            throw boost::system::system_error(error);
        }

        store_recv_msg();
        /* client should have sent their challenge which contains
         * their username encrypted with RSA using the server's public key
         * This is stored in client_msg
         */

        if(RSA_private_decrypt(msg_buf.length(), (unsigned char *)msg_buf.c_str(), tmp_msg_buf, rsa_server_private, RSA_PKCS1_PADDING) < 0){
            ERR_error_string(ERR_get_error(), (char *)tmp_msg_buf);
            std::cerr << "Error decrypting username" << std::endl;
            std::cerr << tmp_msg_buf << std::endl;
            stop();
            return;
        }

        std::cout << "Client's encrypted msg: '" << tmp_msg_buf << "'" << std::endl;

        username = (char *) tmp_msg_buf;

        load_client_public_key();
        initialize_aes_parameters();
        msg_buf.resize(0);
        msg_buf  = username;
        memcpy(&tmp_msg_buf[username.length()], aes_key, sizeof(aes_key));

        int len;
        len = username.length() + sizeof(aes_key);
        unsigned char tmp[4096];
        tmp_msg_buf[len++] = '\0';

        std::cout << len << " username and aes key: ";
        std::cout.write((char*)tmp_msg_buf, len);
        std::cout << std::endl;
        if(tmp_msg_buf[5] == '\0'){
            std::cout << "Username ENDS IN NULL" << std::endl;
        }


        std::cout << len << " : " << RSA_size(rsa_client_public) << std::endl;
        if((len = RSA_public_encrypt(len, tmp_msg_buf, tmp, rsa_client_public, RSA_PKCS1_PADDING)) < 0){
            ERR_error_string(ERR_get_error(), (char *)tmp_msg_buf);
            std::cerr << "Error encrypting username and aes keys with client's public key" << std::endl;
            std::cerr << tmp_msg_buf << std::endl;
            stop();
            return;
        }

        std::cout << len << " : " << RSA_size(rsa_server_private) << std::endl;

        if((len = RSA_private_encrypt(len, tmp, tmp_msg_buf, rsa_server_private, RSA_NO_PADDING)) < 0){
            ERR_error_string(ERR_get_error(), (char *)tmp_msg_buf);
            std::cerr << "Error decrypting username and aes keys with server's private key" << std::endl;
            std::cerr << tmp_msg_buf << std::endl;
            stop();
            return;
        }

        std::cout << "username and aes key encrypted: ";
        std::cout.write((char*)tmp_msg_buf, len);
        std::cout << std::endl;

        msg_buf = (char*) tmp_msg_buf;

        tmp_msg_buf[len++] = '\13';
        tmp_msg_buf[len++] = '\10';

        std::cout << "aes key: ";
        std::cout.write((char*)aes_key, sizeof(aes_key));
        std::cout << std::endl;

        boost::asio::async_write(socket_, boost::asio::buffer(tmp_msg_buf, len), boost::asio::transfer_exactly(len),
            boost::bind(&TCP_Connection::open_encrypted_shell, shared_from_this(),
                boost::asio::placeholders::error,
                boost::asio::placeholders::bytes_transferred));
    }

    void store_recv_msg(){
        /* read everything from the buffer until the MSG_END sequence */
        msg_buf.resize(0);
        char c, p;
        to_recv.read(&p, 1);
        while(to_recv){
            to_recv.read(&c, 1);
            if(p == '\13' && c == '\10'){
                break;
            }
            msg_buf += p;
            p = c;
        }
    }

    void open_encrypted_shell(const boost::system::error_code& error,
        size_t bytes_transferred)
    {
        if(error){
            throw boost::system::system_error(error);
            stop();
        }
        if(bytes_transferred < 0){
            /* Find some error to throw*/
            throw boost::system::system_error(error);
        }

        echo_loop();
    }

    /* aes_iv data should be in aes_iv buffer */
    void read_aes_iv(const boost::system::error_code& error, size_t bytes_transferred){
        if(error){
            std::cerr << error.message() << std::endl;
            stop();
            return;
        }
        std::cout << "Bytes read for iv: " << bytes_transferred << " : " << sizeof(aes_iv) <<std::endl;
        memset(aes_data_enc, 0, sizeof(aes_data_enc));
        boost::asio::async_read(socket_, boost::asio::buffer(aes_data_enc,sizeof(aes_data_enc)),
            boost::asio::transfer_exactly(sizeof(aes_data_enc)),
                boost::bind(&TCP_Connection::read_aes_enc, shared_from_this(),
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
    }

    /* aes_data_enc should be in aes_data_enc */
    void read_aes_enc(const boost::system::error_code& error, size_t bytes_transferred){
        if(error){
            std::cerr << error.message() << std::endl;
            stop();
            return;
        }

        std::cout << "Bytes read for aes: " << bytes_transferred << " : " << sizeof(aes_data_enc) <<std::endl;
        std::cout << "enc:";
        std::cout.write((char*)aes_data_enc, 32);
        std::cout << std::endl;
        memset(aes_data_plain, 0, sizeof(aes_data_plain));
        AES_cbc_encrypt(aes_data_enc, aes_data_plain, sizeof(aes_data_plain), aes_dec, aes_iv, AES_DECRYPT);
        std::cout << username << ": " << aes_data_plain << std::endl;
        RAND_bytes(aes_iv, sizeof(aes_iv));

        boost::asio::async_write(socket_, boost::asio::buffer(aes_iv,sizeof(aes_iv)),
            boost::asio::transfer_exactly(sizeof(aes_iv)),
                boost::bind(&TCP_Connection::write_aes_iv, shared_from_this(),
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
    }

    /* aes_iv should have been written */
    void write_aes_iv(const boost::system::error_code& error, size_t bytes_transferred){
        if(error){
            std::cerr << error.message() << std::endl;
            stop();
            return;
        }

        std::cout << "Bytes written for iv : " << bytes_transferred << " : " << sizeof(aes_iv) <<std::endl;
        AES_cbc_encrypt(aes_data_plain, aes_data_enc, sizeof(aes_data_enc), aes_enc, aes_iv, AES_ENCRYPT);

        boost::asio::async_write(socket_, boost::asio::buffer(aes_data_enc, sizeof(aes_data_enc)), boost::asio::transfer_exactly(sizeof(aes_data_enc)),
                boost::bind(&TCP_Connection::write_aes_enc, shared_from_this(),
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
    }

    /* aes_data_enc should have been written */
    void write_aes_enc(const boost::system::error_code& error, size_t bytes_transferred){
        if(error){
            std::cerr << error.message() << std::endl;
            stop();
            return;
        }
        std::cout << "Bytes sent for enc: " << bytes_transferred << " : " << sizeof(aes_data_enc) <<std::endl;
        boost::asio::async_read(socket_, boost::asio::buffer(aes_iv, sizeof(aes_iv)),
            boost::asio::transfer_exactly(sizeof(aes_iv)),
            boost::bind(&TCP_Connection::read_aes_iv, shared_from_this(),
                boost::asio::placeholders::error,
                boost::asio::placeholders::bytes_transferred));
    }


    void echo_loop(){
        memset(aes_iv, 0, sizeof(aes_iv));
        boost::asio::async_read(socket_, boost::asio::buffer(aes_iv,sizeof(aes_iv)), boost::asio::transfer_exactly(sizeof(aes_iv)),
            boost::bind(&TCP_Connection::read_aes_iv, shared_from_this(),
                boost::asio::placeholders::error,
                boost::asio::placeholders::bytes_transferred));
    }

    tcp::socket socket_;
    std::ostream to_send;
    std::istream to_recv;
    boost::asio::streambuf read_buf;
    boost::asio::streambuf write_buf;
    std::string msg_buf;
    std::string username;
    std::string rsa_dir;

    RSA *rsa_server_private;
    RSA *rsa_server_public;
    RSA *rsa_client_public;
    unsigned char aes_key[256/8];
    unsigned char aes_iv[AES_BLOCK_SIZE];
    unsigned char aes_data_plain[1024];
    unsigned char aes_data_enc[1024];
    AES_KEY *aes_enc, *aes_dec;
    unsigned char tmp_msg_buf[256 + sizeof(MSG_END)];
};

class TCP_Server
{
public:
    TCP_Server(boost::asio::io_service& io, std::string& rsa_dir)
        : acceptor_(io, tcp::endpoint(tcp::v4(), PORT_INT)),
          rsa_dir(rsa_dir)
    {
        start_accept();
    }

private:
    void start_accept()
    {
        // create a new connection
        TCP_Connection::pointer new_connection =
            TCP_Connection::create(acceptor_.get_io_service(), rsa_dir);

        // setup what to call when someone connects
        acceptor_.async_accept(new_connection->socket(),
            boost::bind(&TCP_Server::handle_accept, this, new_connection,
                boost::asio::placeholders::error));

    }

    void handle_accept(TCP_Connection::pointer new_connection,
        const boost::system::error_code& error)
    {
        if(!error)
        {
            new_connection->start();
        }
        start_accept();
    }

    tcp::acceptor acceptor_;
    std::string rsa_dir;
};

int main(void){
    try{
        // required for all io operations through boost
        boost::asio::io_service io;
        std::string rsa_dir("../server/");
        TCP_Server server(io, rsa_dir);

        io.run();
    }catch (std::exception& e){
        std::cerr << e.what() << std::endl;
    }

    return 0;
}

