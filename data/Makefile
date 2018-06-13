sdn-one-pps.1packet.hex : sdn-one-pps.1packet.raw
	> $@
	od -t x1 -A none $< | while read f; do echo "..\"$$f\"" >> $@; done
