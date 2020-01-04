#include <stdio.h>
#include <Timer.h>
#include "BlinkToRadio.h"

module BlinkToRadioC {
	uses interface Boot;
	uses interface Leds;
	uses interface Timer<TMilli> as Timer0;
	uses interface Packet;
	uses interface AMPacket;
	uses interface AMSend;
	uses interface Receive;
	uses interface SplitControl as AMControl;
	uses interface TAKS;
}
implementation {

	uint16_t counter;
	message_t pkt;
	bool busy = FALSE;

	uint8_t LKC[32];
	uint8_t sTKC[32];
	uint8_t dTKC[32];

	void setLeds(uint16_t val) {
		if (val & 0x01)
			call Leds.led0On();
		else
			call Leds.led0Off();
		if (val & 0x02)
			call Leds.led1On();
		else
			call Leds.led1Off();
		if (val & 0x04)
			call Leds.led2On();
		else
			call Leds.led2Off();
	}

	event void Boot.booted() {
		char *LKCc, *dTKCc, *sTKCc;
		if (TOS_NODE_ID == 0) {
			LKCc = LKC_0;
			dTKCc = TKC_0_1;
			sTKCc = TKC_1_0;
		} else {
			LKCc = LKC_1;
			dTKCc = TKC_1_0;
			sTKCc = TKC_0_1;
		}
		call TAKS.ComponentFromHexString(LKC, LKCc);
		call TAKS.ComponentFromHexString(dTKC, dTKCc);
		call TAKS.ComponentFromHexString(sTKC, sTKCc);
		call AMControl.start();
	}

	event void AMControl.startDone(error_t err) {
		if (err == SUCCESS) {
			printf("Starting timer...\r\n");
			call Timer0.startPeriodic(TIMER_PERIOD_MILLI);
		}
		else {
			call AMControl.start();
		}
	}

	event void AMControl.stopDone(error_t err) {
	}

	event void Timer0.fired() {
		BlinkToRadioMsg temp;
		int i;
		counter++;
		if (!busy) {
			BlinkToRadioMsg* btrpkt = (BlinkToRadioMsg*)(call Packet.getPayload(&pkt, sizeof(BlinkToRadioMsg)));
			if (btrpkt == NULL) {
				call Leds.led0On();
				return;
			}

			temp.payload[0] = counter;
			memcpy(&temp.payload[1], "TAKS test 1234\0", 15);

			call TAKS.Encrypt_pw(btrpkt->payload, temp.payload, 16, btrpkt->mac, btrpkt->kri, LKC, sTKC, dTKC);

			if (call AMSend.send(AM_BROADCAST_ADDR, &pkt, sizeof(BlinkToRadioMsg)) == SUCCESS) {
				busy = TRUE;
			}
			else {
				printf("Cannot send\r\n");
				call Leds.led0On();
			}
		}
	}

	event void AMSend.sendDone(message_t* msg, error_t err) {
		if (&pkt == msg) {
			busy = FALSE;
		}
	}

	event message_t* Receive.receive(message_t* msg, void* payload, uint8_t len){
		BlinkToRadioMsg temp;
		if (len == sizeof(BlinkToRadioMsg)) {
			int i, r;
			BlinkToRadioMsg* btrpkt = (BlinkToRadioMsg*)payload;
			printf("Received: ");
			for (i = 0; i < 16; ++i) {
				printf("%02x ", btrpkt->payload[i]);
			}
			r = call TAKS.Decrypt_pw(temp.payload, btrpkt->payload, 16, btrpkt->mac, btrpkt->kri, LKC);
			printf(" -> (%d). Decrypted: ", r);
			for (i = 0; i < 16; ++i) {
				printf("%02x ", temp.payload[i]);
			}
			printf("\r\n");
			if (r != -1) {
				setLeds(temp.payload[0]);
			}
		}
		return msg;
	}
}
