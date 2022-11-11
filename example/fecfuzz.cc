#include "api/array_view.h"
#include "ulpfec/ulpfec_generator.h"
#include <vector>
#include "ulpfec/module_fec_types.h"
#include "ulpfec/byte_io.h"
#include "ulpfec/ulpfec_receiver.h"

using namespace webrtc;

UlpfecGenerator ulpfec_generator_;
std::unique_ptr<UlpfecReceiver> receiver_;

void RtpHeaderParse(RTPHeader &header, const uint8_t* buffer, size_t size)
{
    header.markerBit = (buffer[1] & 0x80) != 0;
    header.payloadType = buffer[1] & 0x7f;
    header.sequenceNumber = ByteReader<uint16_t>::ReadBigEndian(&buffer[2]);
    header.timestamp = ByteReader<uint32_t>::ReadBigEndian(&buffer[4]);
    header.ssrc = ByteReader<uint32_t>::ReadBigEndian(&buffer[8]);
    header.headerLength = 12;
}

constexpr int kFecPayloadType = 96;
constexpr int kRedPayloadType = 97;
constexpr uint32_t kMediaSsrc = 835424;
struct Packet {
    size_t header_size;
    size_t payload_size;
    uint16_t seq_num;
    bool marker_bit;
};

void PrintHexValue(const char *msg, uint16_t seq, const uint8_t *data, size_t size)
{
    printf("%s:%d\n",msg, seq);

    for (size_t i = 0; i < size; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n\n");
}

class DummyCallback : public RecoveredPacketReceiver {
    void OnRecoveredPacket(const uint8_t* packet, size_t length) override {
        
        static int32_t dumpcount = 1;
        RTPHeader header;
        RtpHeaderParse(header, packet, length);
        printf("seq:%d, count:%d\n", header.sequenceNumber, dumpcount++);
        PrintHexValue("dump", header.sequenceNumber, packet + 12, length - 12);
    }
};

// void TestFecGenerator()
// {
//     UlpfecGenerator ulpfec_generator_;
//     std::vector<Packet> protected_packets;
//     protected_packets.push_back({15, 3, 41, 0});
//     protected_packets.push_back({14, 1, 43, 0});
//     protected_packets.push_back({19, 0, 48, 0});
//     protected_packets.push_back({19, 0, 50, 0});
//     protected_packets.push_back({14, 3, 51, 0});
//     protected_packets.push_back({13, 8, 52, 0});
//     protected_packets.push_back({19, 2, 53, 0});
//     protected_packets.push_back({12, 3, 54, 0});
//     protected_packets.push_back({21, 0, 55, 0});
//     protected_packets.push_back({13, 3, 57, 1});
//     FecProtectionParams params = {117, 3, kFecMaskBursty};
//     ulpfec_generator_.SetFecParameters(params);
//     uint8_t packet[28] = {0};
//     for (Packet p : protected_packets) {
//         if (p.marker_bit) {
//             packet[1] |= 0x80;
//         } else {
//             packet[1] &= ~0x80;
//         }
//         ByteWriter<uint16_t>::WriteBigEndian(&packet[2], p.seq_num);
//         ulpfec_generator_.AddRtpPacketAndGenerateFec(packet, p.payload_size,
//                                                     p.header_size);
//         size_t num_fec_packets = ulpfec_generator_.NumAvailableFecPackets();
//         if (num_fec_packets > 0) {
//             std::vector<std::unique_ptr<RedPacket>> fec_packets =
//                 ulpfec_generator_.GetUlpfecPacketsAsRed(kRedPayloadType,
//                                                         kFecPayloadType, 100);
//             printf("num_fec_packets:%d, fec_packets.size:%d\n", num_fec_packets, fec_packets.size());
//         }
//     }
// }

uint8_t red_payload_type_ = 106;
uint8_t ulpfec_payload_type_ = 103;
uint8_t media_payload_type_ = 98;
uint32_t timestamp_ = 1;
uint16_t seq_no_ = 1;
uint32_t ssrc_ = 123;

void SetPayloadType(uint8_t *data, uint8_t pt)
{
    data[1] = (data[1] & 0x80) | pt;
}

void SetTimestamp(uint8_t *data, uint32_t timestamp)
{
    ByteWriter<uint32_t>::WriteBigEndian(data + 4, timestamp);
}

void SetSequenceNumber(uint8_t *data, uint16_t seq_no)
{
    ByteWriter<uint16_t>::WriteBigEndian(data + 2, seq_no);
}

void SetSsrc(uint8_t *data, uint32_t ssrc)
{
    ByteWriter<uint32_t>::WriteBigEndian(data + 8, ssrc);
}

void SendToNetWork(std::unique_ptr<uint8_t[]> packet, size_t size)
{
    RTPHeader parsed_header;
    RtpHeaderParse(parsed_header, packet.get(), size);

    if (receiver_->AddReceivedRedPacket(parsed_header, packet.get(), size, ulpfec_payload_type_) != 0) {
        return;
    }
    receiver_->ProcessReceivedFec();
}

std::unique_ptr<uint8_t[]> BuildRedPayload(uint8_t *media, size_t size)
{
    std::unique_ptr<uint8_t[]> red_packet(new uint8_t[size + 1]);
    memcpy(red_packet.get(), media, 12);
    red_packet.get()[12] = media_payload_type_;
    memcpy(red_packet.get() + 13, media + 12, size - 12);

    return std::move(red_packet);
}

void TestFecGen(uint8_t *data, size_t size)
{
    std::vector<std::unique_ptr<RedPacket>> fec_packets;

    static int32_t packet_count = 0;
    if (++packet_count % 4 == 0) {
        data[1] |= 0x80;
    } else {
        data[1] &= ~0x80;
    }

    std::unique_ptr<uint8_t[]> media_packet(new uint8_t[size]);
    memcpy(media_packet.get(), data, size);

    SetPayloadType(media_packet.get(), media_payload_type_);
    SetTimestamp(media_packet.get(), timestamp_++);
    SetSequenceNumber(media_packet.get(), seq_no_++);
    SetSsrc(media_packet.get(), ssrc_);

    std::unique_ptr<uint8_t[]> red_packet = BuildRedPayload(media_packet.get(), size);
    SetPayloadType(red_packet.get(), red_payload_type_);

    ulpfec_generator_.AddRtpPacketAndGenerateFec(media_packet.get(), size - 12, 12);
    size_t num_fec_packets = ulpfec_generator_.NumAvailableFecPackets();
    if (num_fec_packets > 0) {
        printf("num_fec_packets:%d\n", num_fec_packets);
        fec_packets = ulpfec_generator_.GetUlpfecPacketsAsRed(red_payload_type_, ulpfec_payload_type_, seq_no_);
    }

    static int32_t sumicast_lost = 1;
    if (sumicast_lost++ % 4 != 0) {
        SendToNetWork(std::move(red_packet), size + 1);
    } else {
        PrintHexValue("loss", seq_no_ - 1, media_packet.get() + 12, size - 12);
    }

    for (const auto &fec_packet : fec_packets) {
        std::unique_ptr<uint8_t[]> rtp_packet(new uint8_t[fec_packet->length()]);
        memcpy(rtp_packet.get(), fec_packet->data(), fec_packet->length());
        SendToNetWork(std::move(rtp_packet), fec_packet->length());
    }
}

int main()
{
    FecProtectionParams params = {117, 3, kFecMaskBursty};
    ulpfec_generator_.SetFecParameters(params);

    DummyCallback callback;
    receiver_.reset(UlpfecReceiver::Create(ssrc_, &callback));

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
        // printf("data len : %d\n", data_len);
        uint8_t payload[1024];
        fread(payload, data_len, 1, fp);

        TestFecGen(payload, data_len);
    }

    return 0;
}