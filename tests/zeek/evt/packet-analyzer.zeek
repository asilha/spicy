# @TEST-REQUIRES: have-zeek-plugin-jit
#
# @TEST-EXEC: ${ZEEK} -r ${TRACES}/raw-layer.pcap raw-layer.spicy raw-layer.evt %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=${SCRIPTS}/canonify-zeek-log btest-diff output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=${SCRIPTS}/canonify-zeek-log btest-diff conn.log
# @TEST-EXEC-FAIL: test -e weird.log
#
## @TEST-GROUP: spicy-core

module PacketAnalyzer::SPICY_RAWLAYER;

export {
	const dispatch_map: PacketAnalyzer::DispatchMap = {
	    [0x4950] = PacketAnalyzer::DispatchEntry($analyzer=PacketAnalyzer::ANALYZER_IP)
	};
}

event zeek_init()
	{
	Spicy::register_packet_analyzer(PacketAnalyzer::ETHERNET::dispatch_map, 0x88b5, "spicy::RawLayer");
	}

event raw::data(data: string)
	{
	print "raw data", data;
	}

# @TEST-START-FILE raw-layer.spicy
module RawLayer;

import zeek;

public type Packet = unit {
    data: bytes &size=19;
    protocol: uint16;

    on %done {
        zeek::forward_packet(self.protocol);
    }
};
# @TEST-END-FILE

# @TEST-START-FILE raw-layer.evt
packet analyzer spicy::RawLayer:
    parse with RawLayer::Packet;

on RawLayer::Packet::data -> event raw::data(self.data);
# @TEST-END-FILE
