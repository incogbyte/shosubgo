package main

import (
    "bufio"
    "flag"
    "fmt"
    "log"
    "os"

    "github.com/incogbyte/shosubgo/apishodan"
)

const Author = "inc0gbyt3"

func main() {
    domain := flag.String("d", "", "> Domain to find subdomains")
    shodanKey := flag.String("s", "", "> Shodan api key")
    verbose := flag.Bool("v", false, "> Show all output")
    fileName := flag.String("o", "", "> Save domains into a file")
    inputFile := flag.String("F", "", "> File containing domains to find subdomains")
    flag.Parse()

    if *domain == "" && *inputFile == "" {
        fmt.Printf("[*] Usage: %s -d target.com -s MYShodaNKey [-F input_file]\n", os.Args[0])
        fmt.Printf("[*] Author: %s\n", Author)
        os.Exit(1)
    }

    apiKey := apishodan.New(*shodanKey)

    var domains []string

    if *domain != "" {
        // Use domain from command-line argument (-d)
        domains = append(domains, *domain)
    }

    if *inputFile != "" {
        // Read domains from file specified by -F flag
        fileDomains, err := readDomainsFromFile(*inputFile)
        if err != nil {
            log.Fatalf("Failed to read domains from file: %v", err)
        }
        domains = append(domains, fileDomains...)
    }

    for _, domainSearch := range domains {
        subdomain, err := apiKey.GetSubdomain(domainSearch)
        if err != nil {
            fmt.Printf("Error fetching subdomains for domain %s: %v\n", domainSearch, err)
            continue
        }

        if len(subdomain.SubDomains) == 0 {
            fmt.Printf("No subdomains found for domain %s\n", domainSearch)
            continue
        }

        if *verbose == true {
            info, err := apiKey.InfoAccount()
            if err != nil {
                fmt.Printf("Error fetching account info: %v\n", err)
                continue
            }
            fmt.Printf("[*] Credits: %d\nScan Credits: %d\n\n", info.QueryCredits, info.ScanCredits)

            for _, v := range subdomain.Data {
                d := v.SubD + subdomain.Domain
                fmt.Printf("[*] Domain: %s\nIP/DNS: %s\nLast Scan made by Shodan: %s\n", d, v.Value, v.LastSeen)
            }
        } else {
            for _, v := range subdomain.SubDomains {
                if *fileName != "" {
                    f, err := os.OpenFile(*fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
                    if err != nil {
                        log.Fatal(err)
                    }
                    defer f.Close()

                    _, err = f.WriteString(v + "\n")
                    if err != nil {
                        log.Fatal(err)
                    }
                    fmt.Println("[*] DONE writing to file:", *fileName)
                }
                fmt.Printf("%s.%s\n", v, domainSearch)
            }
        }
    }
}

func readDomainsFromFile(filename string) ([]string, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var domains []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        domains = append(domains, scanner.Text())
    }
    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return domains, nil
}
