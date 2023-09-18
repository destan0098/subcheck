package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"flag"
	"fmt"
	"github.com/TwiN/go-color"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type DomainResult struct {
	Domain  string
	Port80  bool
	Port443 bool
	IsCDN   bool
	CDNname string
}

func main() {
	fmt.Printf(color.Colorize(color.Green, `Example Of Use : Subcheck.go -i 'C:\Users\**\Desktop\go2\checksubdomains\input.txt' -o 'C:\Users\***\Desktop\go2\checksubdomains\result4.csv'`))
	fmt.Println(color.Colorize(color.Red, "[*] This tool is for training."))
	//This line Give Argumans From Users
	inputfile := flag.String("i", "input.txt", "Input txt File")
	outputfile := flag.String("o", "result.csv", "Output CSV File")
	flag.Parse()
	//	REad Domain List From Text File
	domains := readDomains(*inputfile)

	var wg sync.WaitGroup
	var results []DomainResult

	for _, domain := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			//Check Port 80 Open Or not
			port80, err80 := isPortOpen80(domain)
			//Check Port 443 Open Or not
			port443, err443 := isPortOpen443(domain)
			//Check on CDN Or not
			isCDNs, errCDN, CDNname := isCDN(domain)
			result := DomainResult{
				Domain:  domain,
				Port80:  port80 && err80 == nil,
				Port443: port443 && err443 == nil,
				IsCDN:   isCDNs && errCDN == nil,
				CDNname: CDNname,
			}
			if result.Port80 || port443 {
				fmt.Printf("Domain %s is Opened\n", result.Domain)
				results = append(results, result)
			}
		}(domain)
	}

	wg.Wait()

	writeResults(results, *outputfile)
}

func readDomains(filename string) []string {
	//open file
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		//add list of domain to the list
		domains = append(domains, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}

	return domains
}

func isPortOpen80(domain string) (bool, error) {
	_, err := http.Get("http://" + domain)
	if err == nil {
		//if port 80 opened check the ip
		ipAddr, err := net.LookupIP(domain)

		if err != nil {
			fmt.Printf("%s is down\n", domain)
			return false, err
		}
		fmt.Printf("%s is up (%s)\n", domain, ipAddr[0])
		return true, nil

	} else {
		fmt.Println(color.Colorize(color.Red, "[-] Domain not Resolved"))
		return false, err
	}
}
func isPortOpen443(domain string) (bool, error) {

	_, err := http.Get("https://" + domain)
	if err == nil {
		//chech the port 443 open , if open give ip
		ipAddr, err := net.LookupIP(domain)

		if err != nil {
			fmt.Printf("%s is down\n", domain)
			return false, err
		}
		fmt.Printf("%s is up (%s)\n", domain, ipAddr[0])
		return true, nil

	} else {
		fmt.Println(color.Colorize(color.Red, "[-] Domain not Resolved"))

		return false, err
	}

}
func isCDN(domain string) (bool, error, string) {
	//this function check cdn by header of response http
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: tr}
	resp, err := client.Get("http://" + domain)

	if err != nil {
		fmt.Println(err)
		return false, err, "Not"
	}

	defer resp.Body.Close()

	cdnHeaders := []string{"Akamai", "Cloudflare", "Incapsula", "MaxCDN", "Fastly", "CDN77", "Amazon CloudFront", "KeyCDN"}
	for _, header := range cdnHeaders {
		if strings.Contains(resp.Header.Get("Server"), header) || strings.Contains(resp.Header.Get("X-Cache"), header) || strings.Contains(resp.Header.Get("Via"), header) {
			//if on cdn return true and cdn name
			return true, nil, header
		}
	}
	return false, nil, "Not"
}

func writeResults(results []DomainResult, outputfile string) {
	file, err := os.Create(outputfile)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	//write all in csv file
	writer := csv.NewWriter(file)
	defer writer.Flush()
	writer.Write([]string{"Domain", "Port 80", "Port 443", "Is CDN", "CDN Name"})
	for _, result := range results {
		writer.Write([]string{result.Domain, fmt.Sprintf("%v", result.Port80), fmt.Sprintf("%v", result.Port443), fmt.Sprintf("%v", result.IsCDN), fmt.Sprintf("%v", result.CDNname)})
	}
}
