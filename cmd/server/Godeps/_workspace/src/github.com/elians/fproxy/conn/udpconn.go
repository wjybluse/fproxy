package conn

///default use as tunnel to improve speed
import "net"

type udpclient struct {
	Conn *net.UDPConn
}

//NewUDPClient ...
func NewUDPClient(host string, secure bool) (Connector, error) {
	addr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	return &udpclient{
		Conn: conn,
	}, nil
}

func (client *udpclient) Connect() (net.Conn, error) {
	return client.Conn, nil
}

func (client *udpclient) Close() {
	if client.Conn != nil {
		client.Conn.Close()
	}
}
