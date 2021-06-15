package client
import (
	pb "github.com/devopsfaith/krakend-ce/grpc/authentication_service/service"
	"google.golang.org/grpc"
)

func NewauthenticationClient(address string) (pb.AuthenticationClient, error) {
	conn, err := grpc.Dial(address, grpc.WithInsecure())

	if err != nil {
		return nil, err
	}

	client := pb.NewAuthenticationClient(conn)

	return client, nil
}
