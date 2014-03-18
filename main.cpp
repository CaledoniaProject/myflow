#include <pcap.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
#define MAX_ENTRY_COUNT 50000

#include <cstring>
#include <cstdio>
#include <vector>
#include <cstdlib>
#include <unordered_map>
#include <iterator>
#include <list>
#include <algorithm>
#include <iostream>

#ifdef SECURE
#include <antidebug.h>
#endif

//#define DEBUG

#ifdef DEBUG 
#define D(x) x
#else 
#define D(x)
#endif

#define PPP_HDRLEN 4

using namespace std;
unordered_map<string, string> bytesMapping;
list<string> bytesLRU;

void addpair (time_t *ts, const string & key, string & value,
        unordered_map<string, string> & data,
        list<string> & lru);
void dumppair (const unordered_map<string, string> & data);
bool process_http (time_t *ts, const string & id, string & bytes);
bool KMP_getContentLength (const char *heystack, size_t hlen, size_t & result);
char *strnstr (const char *s, const char *find, size_t slen);
void help ();
void loop (pcap_t *handle);

int main(int argc, char **argv)
{
    pcap_t *handle;
    struct bpf_program bpf;
    char errbuf[PCAP_ERRBUF_SIZE], *device = NULL, *filter = NULL;
    bpf_u_int32 net, mask;
    int arg, snaplen = 0;

    while ((arg = getopt (argc, argv, "i:hf:s:")) != -1)
    {
        switch (arg)
        {
            case 'i':
                device = optarg;
                break;
            case 'f':
                filter = optarg;
                break;
            case 's':
                snaplen = atoi (optarg);
                break;
            case 'h':
                help ();
                break;
            default:
                break;
        }
    }

    if (argc < 2 && ! device)
        help ();

    bytesMapping.reserve (MAX_ENTRY_COUNT);

    // alive
    if (device)
    {
        if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) 
        {
            fprintf(stderr, "Can't get netmask for device %s: %s\n", device, errbuf);
            exit (1);
        }

        if (! (handle = pcap_open_live (device, BUFSIZ, 1, 0, errbuf)))
        {
            fprintf(stderr, "pcap_open_live: %s\n", errbuf);
            exit (1);
        }

        if (filter != NULL && -1 == pcap_compile (handle, &bpf, filter, 0, mask))
        {
            fprintf(stderr, "pcap_compile: %s\n", errbuf);
            exit (1);
        }

        if (filter && -1 == pcap_setfilter (handle, &bpf))
        {
            fprintf(stderr, "pcap_setfilter: %s\n", errbuf);
            exit (1);
        }

        if (-1 == pcap_set_snaplen (handle, snaplen))
        {
            fprintf(stderr, "pcap_set_snaplen: %s\n", errbuf);
            exit (1);
        }

        loop(handle);
        pcap_close(handle);
    }
    // offline
    else 
    {

        for (int i = optind; i < argc; ++ i)
        {
            if (! (handle = pcap_open_offline(argv[i], errbuf)))
            {
                fprintf(stderr, "Couldn't open pcap file %s: %s\n", argv[i], errbuf);
                continue;
            }

            loop(handle);
            pcap_close(handle);  //close the pcap file

        } // argv
    }

    dumppair (bytesMapping);

    return 0; //done
} // main()

void dumppair (const unordered_map<string, string> & data)
{
    for (unordered_map<string, string>::const_iterator iter = data.begin();
            iter != data.end(); ++ iter)
    {
        cerr << "ID: " << iter->first << endl;
        cerr << "Content: " << iter->second << endl << endl;
    }
}

void addpair (time_t *ts, const string & key, string & value, unordered_map<string, string> & data, list<string> & lru)
{
    unordered_map<string, string>::iterator iter = data.find (key);
    if (iter == data.end())
    {
        if (process_http (ts, key, value))
            return;

        if (data.size() == MAX_ENTRY_COUNT)
        {
            data.erase (lru.front());
            lru.pop_front();
        }

        data[key] = value;
        lru.push_back (key);
    }
    else
    {
        string combined = (*iter).second + value;
        if (process_http (ts, key, combined))
        {
            data.erase (key);
            return;
        }

        data[key] = combined;
    }
}

bool lower_test (const char & l, const char & r) {
    return (std::tolower(l) == std::tolower(r));
}

void dump_packet (time_t *ts, const string & id, const string & bytes)
{
    cout << "-- Packet size: " << bytes.size() << ", Time: " << *ts << ", Tuple: " << id << endl;
    for (string::const_iterator iter = bytes.begin();
            iter != bytes.end();
            ++ iter)
    {
        if (isprint (*iter) || *iter == '\n' || *iter == '\r')
            cout << *iter;
        else
            cout << ".";
    }

    cout << endl;
    cout << "-- End Packet --" << endl << endl;
}

bool process_http (time_t *ts, const string & id, string & bytes)
{
    // content-length
    size_t length;

    // std::find sucks
    size_t minlen = std::min<size_t> (bytes.size(), 5);
    if (strnstr (bytes.c_str(), "GET ", minlen) != bytes.c_str()
            && strnstr (bytes.c_str(), "POST ", minlen) != bytes.c_str())
        return true;

    // Incomplete, either GET or POST
    size_t payloadPos = bytes.find ("\r\n\r\n");
    if (payloadPos == bytes.npos)
    {
        return false;
    }

    // No Content-Length header, ignore payloads even if supplied
    if (! KMP_getContentLength (bytes.c_str(), payloadPos, length))
    {
        // Ending here
        if (payloadPos < bytes.size() - 1)
        {
            D(
                    cerr << "Packe is complete (GET)");
            dump_packet (ts, id, bytes);
            return true;
        }
        else
        {
            // pos of payload + length("\r\n\r\n")
            size_t length = payloadPos + 4;

            D(
                    size_t actual = bytes.size();
                    cerr << " --- Exception --- " << id << endl
                    << "HTTP Pipelining detected! Consumed " << length << " bytes. "
                    << "remaining: " << actual - length << " bytes" << endl
                    << "The multiple bytes are: " << bytes << endl << endl;);

            dump_packet (ts, id, bytes.substr(0, length));

            bytes.erase (0, length);
            return process_http (ts, id, bytes);
        }
    }
    else
    {
        size_t actual = bytes.size() - payloadPos - 4;

        if (length == actual)
        {
            D(
                    cerr << "Packet is complete (POST)" << endl;);
            dump_packet (ts, id, bytes);
            return true;
        }
        else if (actual > length)
        {
            D(cerr << " --- Exception --- " << id << endl
                    << "HTTP Pipelining detected! Consumed " << length << " bytes. "
                    << "remaining: " << actual - length << " bytes" << endl
                    << "The multiple bytes are: " << bytes << endl << endl;);

            dump_packet (ts, id, bytes.substr(0, length));

            bytes.erase (0, payloadPos + 4 + length);
            return process_http (ts, id, bytes);
        }
        else
        {
            D(cerr << " --- Exception --- Unfinished POST request: " << id << endl
                    << "Expecting: " << length << ", actual: " << actual << endl
                    << "Current we have: " << bytes << endl
                    << endl << "--- FINI Exception ---" << endl << endl;);
        }
    }

    return false;
}


bool KMP_getContentLength (const char *heystack, size_t hlen, size_t & result)
{
    static const char *needle = "content-length:";
    static int nlen = strlen (needle);

    result = 0;

    for (int i = 0; i < hlen; ++ i)
    {
        for (int j = 0; j < nlen; ++ j)
        {
            if (tolower (heystack[i ++]) != tolower (needle [j]))
            {
                -- i; break;
            }

            if (j == nlen - 1)
            {
                for (; i < hlen; ++ i)
                {
                    if (isdigit (heystack[i]))
                        result = result * 10 + heystack[i] - '0';
                    else if (heystack[i] == '\n')
                        break;
                }

                return true;
            }
        }
    }

    return false;
}

void help ()
{
    fprintf(stderr, "myflow [input pcaps] ...\n"
            "-or-\n"
            "myflow -i eth0 ...\n\n"
            "arguments: \n"
            " -f bpf filter\n"
            " -s snaplen\n"
            " -h show this dialog\n\n");
    exit(1);
}

char *strnstr (const char *s, const char *find, size_t slen)
{
    char c, sc;
    size_t len;

    if ((c = *find++) != '\0') {
        len = strlen(find);
        do {
            do {
                if (slen-- < 1 || (sc = *s++) == '\0')
                    return (NULL);
            } while (sc != c);
            if (len > slen)
                return (NULL);
        } while (strncmp(s, find, len) != 0);
        s--;
    }
    return ((char *)s);
}

void loop (pcap_t *handle)
{
    struct pcap_pkthdr header;
    const u_char *packet;
    int dlt = pcap_datalink (handle);

    while (NULL != (packet = pcap_next(handle, &header)))
    {
        bpf_u_int32 caplen = header.caplen, offset = 0;

        switch (dlt)
        {
            case DLT_EN10MB:
            case DLT_IEEE802:
                {
                    // ether header
                    if (caplen <= sizeof (struct ether_header))
                    {
                        cerr << "eth" << endl;
                        continue;
                    }

                    struct ether_header *eth_header = (struct ether_header *) packet;
                    offset += sizeof (ether_header);
                    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
                    {
                        cerr << "not a ether frame" << endl;
                        continue;
                    }
                }
                break;

            case DLT_PPP:
                if (caplen < PPP_HDRLEN)
                {
                    D(
                            cerr << "Incomplete PPP frame" << endl;);
                    continue;
                }

                offset += PPP_HDRLEN;
                break;

            case DLT_RAW:
                break;

            default:
                D(
                        cerr << "Unsupported datalink type: " << dlt << endl;);
                continue;
        }

        // ip header
        if (offset >= caplen)
        {
            cerr << "ip" << endl;
            continue;
        }
        struct ip *ip_header = (struct ip *) (packet + offset);
        offset += ip_header->ip_hl * 4;

        // tcp header
        if (offset >= caplen)
        {
            cerr << "tcp" << endl;
            continue;
        }
        struct tcphdr *tcp_header = (struct tcphdr *) (packet + offset);
        offset += tcp_header->th_off * 4;

        if (tcp_header->syn || tcp_header->rst)
        {
//            cerr << "SYN / RST packet" << endl;
            continue;
        }

        // http data
        if (offset >= caplen)
        {
//            cerr << "no more tcp, but caplen was " << caplen << endl;
            continue;
        }

        char *srcip = strdup (inet_ntoa (ip_header->ip_src)),
             *dstip = strdup (inet_ntoa (ip_header->ip_dst)),
             tupleID [255];

        snprintf (tupleID, 255, "%s:%d:%s:%d",
                srcip, ntohs (tcp_header->th_sport),
                dstip, ntohs (tcp_header->th_dport));

        string value ((char*) (packet + offset), caplen - offset);
        string key (tupleID);

        addpair (&header.ts.tv_sec, key, value, bytesMapping, bytesLRU);

        delete srcip; delete dstip;

    } //end internal loop for reading packets (all in one file)

}
