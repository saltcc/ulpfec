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

constexpr size_t kDefaultPacketSize = 1500;
constexpr uint8_t red_payload_type_ = 106;
constexpr uint8_t ulpfec_payload_type_ = 103;
constexpr uint8_t media_payload_type_ = 98;
constexpr uint16_t rtp_header_len_ = 12;
uint32_t timestamp_ = 1;
uint16_t seq_no_ = 1;
uint32_t ssrc_ = 123;

class RtpPacket 
{
public:
    RtpPacket() : RtpPacket(kDefaultPacketSize) {}
    RtpPacket(size_t capacity)
        : capacity_(capacity), buffer_(new uint8_t[capacity]) {
    }
    RtpPacket(const RtpPacket&) = default;
    ~RtpPacket() {}
    void SetPayloadType(uint8_t pt) {
        buffer_[1] = (buffer_[1] & 0x80) | pt;
    }
    void SetTimestamp(uint32_t timestamp) {
        ByteWriter<uint32_t>::WriteBigEndian(&buffer_[4], timestamp);
    }
    void SetSequenceNumber(uint16_t seq_no) {
        ByteWriter<uint16_t>::WriteBigEndian(&buffer_[2], seq_no);
    }
    void SetSsrc(uint32_t ssrc) {
        ByteWriter<uint32_t>::WriteBigEndian(&buffer_[8], ssrc);
    }
    void GetRtpHeader(RTPHeader &header) {
        header.markerBit = (buffer_[1] & 0x80) != 0;
        header.payloadType = buffer_[1] & 0x7f;
        header.sequenceNumber = ByteReader<uint16_t>::ReadBigEndian(&buffer_[2]);
        header.timestamp = ByteReader<uint32_t>::ReadBigEndian(&buffer_[4]);
        header.ssrc = ByteReader<uint32_t>::ReadBigEndian(&buffer_[8]);
        header.headerLength = 12;
    }
    void SetData(const uint8_t* data, size_t length){
        if (data == nullptr || length > capacity_) return;
        memcpy(buffer_.get(), data, length);
        length_ = length;
    }
    void SetLength(size_t length) {length_ = length;}
    uint8_t* data() {
        return buffer_.get();
    }
    size_t length() {
        return length_;
    }
private:
    size_t length_{0};
    size_t capacity_;
    std::unique_ptr<uint8_t[]> buffer_;
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

void SendToNetWork(std::unique_ptr<RtpPacket> packet)
{
    RTPHeader parsed_header;
    packet->GetRtpHeader(parsed_header);

    if (receiver_->AddReceivedRedPacket(parsed_header, packet->data(), packet->length(), ulpfec_payload_type_) != 0) {
        return;
    }
    receiver_->ProcessReceivedFec();
}

std::unique_ptr<RtpPacket> BuildRedPayload(RtpPacket *media)
{
    std::unique_ptr<RtpPacket> packet(new RtpPacket(media->length() + 1));
    memcpy(packet->data(), media->data(), rtp_header_len_);
    packet->data()[rtp_header_len_] = media_payload_type_;
    memcpy(packet->data() + rtp_header_len_ + 1, media->data() + 12, media->length() - 12);
    packet->SetLength(media->length() + 1);
    return std::move(packet);
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

    std::unique_ptr<RtpPacket> mediaPacket(new RtpPacket(size));
    mediaPacket->SetData(data, size);

    mediaPacket->SetPayloadType(media_payload_type_);
    mediaPacket->SetTimestamp(timestamp_++);
    mediaPacket->SetSequenceNumber(seq_no_++);
    mediaPacket->SetSsrc(ssrc_);

    std::unique_ptr<RtpPacket> red_packet = BuildRedPayload(mediaPacket.get());
    red_packet->SetPayloadType(red_payload_type_);

    ulpfec_generator_.AddRtpPacketAndGenerateFec(mediaPacket->data(), mediaPacket->length() - rtp_header_len_, rtp_header_len_);
    size_t num_fec_packets = ulpfec_generator_.NumAvailableFecPackets();
    if (num_fec_packets > 0) {
        printf("num_fec_packets:%d\n", num_fec_packets);
        fec_packets = ulpfec_generator_.GetUlpfecPacketsAsRed(red_payload_type_, ulpfec_payload_type_, seq_no_);
    }

    static int32_t sumicast_lost = 1;
    if (sumicast_lost++ % 4 != 0) {
        SendToNetWork(std::move(red_packet));
    } else {
        PrintHexValue("loss", seq_no_ - 1, mediaPacket->data() + rtp_header_len_, mediaPacket->length() - rtp_header_len_);
    }

    for (const auto &fec_packet : fec_packets) {
        std::unique_ptr<RtpPacket> rtp_packet(new RtpPacket(fec_packet->length()));
        rtp_packet->SetData(fec_packet->data(), fec_packet->length());
        SendToNetWork(std::move(rtp_packet));
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