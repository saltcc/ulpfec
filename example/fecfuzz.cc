#include "api/array_view.h"
#include "ulpfec/ulpfec_generator.h"
#include <vector>
#include "ulpfec/module_fec_types.h"
#include "ulpfec/byte_io.h"

using namespace webrtc;

constexpr int kFecPayloadType = 96;
constexpr int kRedPayloadType = 97;
constexpr uint32_t kMediaSsrc = 835424;
struct Packet {
    size_t header_size;
    size_t payload_size;
    uint16_t seq_num;
    bool marker_bit;
};

class DummyCallback : public RecoveredPacketReceiver {
  void OnRecoveredPacket(const uint8_t* packet, size_t length) override {}
};

void TestFecGenerator()
{
    UlpfecGenerator ulpfec_generator_;
    std::vector<Packet> protected_packets;
    protected_packets.push_back({15, 3, 41, 0});
    protected_packets.push_back({14, 1, 43, 0});
    protected_packets.push_back({19, 0, 48, 0});
    protected_packets.push_back({19, 0, 50, 0});
    protected_packets.push_back({14, 3, 51, 0});
    protected_packets.push_back({13, 8, 52, 0});
    protected_packets.push_back({19, 2, 53, 0});
    protected_packets.push_back({12, 3, 54, 0});
    protected_packets.push_back({21, 0, 55, 0});
    protected_packets.push_back({13, 3, 57, 1});
    FecProtectionParams params = {117, 3, kFecMaskBursty};
    ulpfec_generator_.SetFecParameters(params);
    uint8_t packet[28] = {0};
    for (Packet p : protected_packets) {
        if (p.marker_bit) {
            packet[1] |= 0x80;
        } else {
            packet[1] &= ~0x80;
        }
        ByteWriter<uint16_t>::WriteBigEndian(&packet[2], p.seq_num);
        ulpfec_generator_.AddRtpPacketAndGenerateFec(packet, p.payload_size,
                                                    p.header_size);
        size_t num_fec_packets = ulpfec_generator_.NumAvailableFecPackets();
        if (num_fec_packets > 0) {
            std::vector<std::unique_ptr<RedPacket>> fec_packets =
                ulpfec_generator_.GetUlpfecPacketsAsRed(kRedPayloadType,
                                                        kFecPayloadType, 100);
            printf("num_fec_packets:%d, fec_packets.size:%d\n", num_fec_packets, fec_packets.size());
        }
    }
}

void TestFecReceiver(const uint8_t* data, size_t size)
{

}

int main()
{
    const char *filename = "rtp.raw";
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL){
        printf("fp null\n");
        return 0;
    }
    while (!feof(fp)){
        uint16_t data_len = 0;
        fread(&data_len, 2, 1, fp);
        if (data_len == 0){
            printf("break\n");
            break;
        }
        printf("data len : %d\n", data_len);
        uint8_t payload[1024];
        fread(payload, data_len, 1, fp);
    }
    return 0;
}