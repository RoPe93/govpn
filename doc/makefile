all: govpn.info govpn.html

govpn.info: govpn.texi handshake.utxt
	makeinfo govpn.texi

handshake.utxt: handshake.txt
	plantuml -tutxt handshake.txt

govpn.html: govpn.texi handshake.utxt
	makeinfo --html -o govpn.html govpn.texi
