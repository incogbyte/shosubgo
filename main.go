package main

import (
    "bufio"
    "encoding/json"
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
    inputFile := flag.String("f", "", "> File containing domains to find subdomains")
    jsonFlag := flag.Bool("json", false, "> Save output in JSON format")
    flag.Parse()

    if *domain == "" && *inputFile == "" {
        fmt.Printf("[*] Usage: %s -d target.com -s shodanKey [-f input_file]\n", os.Args[0])
        fmt.Printf("[*] Author: %s\n", Author)
        os.Exit(1)
    }

    apiKey := apishodan.New(*shodanKey)

    var domains []string

    if *domain != "" {
        domains = append(domains, *domain)
    }

    if *inputFile != "" {
        fileDomains, err := readDomainsFromFile(*inputFile)
        if err != nil {
            log.Fatalf("Failed to read domains from file: %v", err)
        }
        domains = append(domains, fileDomains...)
    }

    var outputFile *os.File
    var err error
    if *fileName != "" {
        outputFile, err = os.OpenFile(*fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
            log.Fatalf("Failed to open output file: %v", err)
        }
        defer outputFile.Close()
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

        if *verbose {
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
            if *jsonFlag {
                // Convert full subdomains to a slice
                var fullSubdomains []string
                for _, sub := range subdomain.SubDomains {
                    fullSubdomains = append(fullSubdomains, fmt.Sprintf("%s.%s", sub, domainSearch))
                }

                jsonData, err := json.MarshalIndent(fullSubdomains, "", "  ")
                if err != nil {
                    log.Fatal("Error marshaling JSON:", err)
                }

                if outputFile != nil {
                    _, err = outputFile.Write(jsonData)
                    if err != nil {
                        log.Fatal(err)
                    }
                    _, err = outputFile.WriteString("\n")
                    if err != nil {
                        log.Fatal(err)
                    }
                    fmt.Println("[*] DONE writing JSON to file:", *fileName)
                } else {
                    fmt.Println(string(jsonData))
                }
            } else {
                for _, v := range subdomain.SubDomains {
                    fullDomain := fmt.Sprintf("%s.%s", v, domainSearch)
                    if outputFile != nil {
                        _, err := outputFile.WriteString(fullDomain + "\n")
                        if err != nil {
                            log.Fatal(err)
                        }
                    }
                    fmt.Println(fullDomain)
                }
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
