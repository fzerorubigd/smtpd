package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/fzerorubigd/smtpd"
	"github.com/jhillyerd/enmime"
)

func handler(remoteAddr net.Addr, from string, to []string, data []byte) {
	fmt.Println("------", string(data), "-----")
	e, err := enmime.ReadEnvelope(bytes.NewReader(data))
	if err != nil {
		log.Println(err)
		return
	}

	fmt.Println(e)
}

func debugHandler(r net.Addr, verb string, text string) {
	log.Println(r.String(), verb, text)
}

func main() {
	hn, _ := os.Hostname()
	var (
		address  = flag.String("address", ":2525", "the address for smtp server")
		appName  = flag.String("appname", "smtpdump", "the app name")
		hostName = flag.String("hostname", hn, "host name")
	)
	flag.Parse()
	ctx := cliContext()

	opts := []smtpd.OptionSetter{
		smtpd.WithAddress(*address),
		smtpd.WithAppName(*appName),
		smtpd.WithHostname(*hostName),
		smtpd.WithDebug(debugHandler),
		smtpd.AllowAuthMechanisms("LOGIN", true),
		smtpd.WithAuthHandler(func(remoteAddr net.Addr, mechanism string, username []byte, password []byte, shared []byte) (bool, error) {
			fmt.Println(remoteAddr.String(), "AUTH: ", mechanism, string(username), string(password), string(shared))
			return true, nil
		}, true),
	}

	srv, err := smtpd.NewServer(handler, opts...)
	if err != nil {
		log.Fatal(err)
	}

	if err := srv.ListenAndServeContext(ctx); err != nil {
		log.Fatal(err)
	}
}

func cliContext() context.Context {
	var sig = make(chan os.Signal, 4)
	ctx, cancel := context.WithCancel(context.Background())
	signal.Notify(sig, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGABRT)
	go func() {
		select {
		case <-sig:
			cancel()
		}
	}()

	return ctx
}
