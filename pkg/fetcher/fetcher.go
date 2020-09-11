package fetcher

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/deepin-cve/tracker/pkg/db"
)

const (
	nvdPrefix = "https://nvd.nist.gov/vuln/detail/"
)

func Fetch(uri string, filterList []string) (db.CVEList, error) {
	var values = make(url.Values)
	values["filter"] = filterList
	params := values.Encode()
	if len(params) != 0 {
		uri += "?" + params
	}
	fmt.Println("Fetch uri:", uri)

	doc, err := goquery.NewDocument("https://cve.uniontech.com/stable.html")
	if err != nil {
		fmt.Println("Failed to new document tree:", err)
		return nil, err
	}

	// only a table
	tableElm := doc.Find("table")
	if tableElm == nil {
		fmt.Println("No table exists")
		return nil, fmt.Errorf("invalid uri: no table exists")
	}
	var cveList db.CVEList
	tableElm.Find("tr").Each(func(rowIdx int, rowEle *goquery.Selection) {
		// ignore header
		var cve db.CVE
		rowEle.Find("td").Each(func(cellIdx int, cellEle *goquery.Selection) {
			switch cellIdx {
			case 0:
				cve.Package = cellEle.Text()
			case 1:
				cve.Cve_id = cellEle.Text()
			}
		})
		if len(cve.Cve_id) != 0 {
			cveList = append(cveList, &cve)
		}
	})

	cveList.FixPackage()
	// cveList.Dump()
	return cveList, nil
}

// FetchFromFile parse html document from file
func FetchFromFile(filename string) {
	datas, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Failed to read file:", err)
		return
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(datas))
	if err != nil {
		fmt.Println("Failed to new document tree:", err)
		return
	}

	doc.Find("table").Each(func(i int, tableEle *goquery.Selection) {
		tableEle.Find("tr").Each(func(ii int, rowEle *goquery.Selection) {
			var headers []string
			var rows []string
			rowEle.Find("th").Each(func(iii1 int, thEle *goquery.Selection) {
				headers = append(headers, thEle.Text())
			})
			rowEle.Find("td").Each(func(iii2 int, tdEle *goquery.Selection) {
				var row = tdEle.Text()
				tdEle.Find("a").Each(func(iiii int, aEle *goquery.Selection) {
					href, _ := aEle.Attr("href")
					if href != "" {
						row += " - " + href
					}
				})
				rows = append(rows, row)
			})
			if len(headers) != 0 {
				fmt.Println(ii, ", headers:", headers)
			}
			fmt.Println(ii, ", data:", rows)
		})
	})
}

func Fetch_linux(url, edition string) (db.Linux_core, error) {
	url = url + edition + "/" + edition + "_security.txt"
	res, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		log.Fatalf("status code error: %d %s", res.StatusCode, res.Status)
	}
	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	var List db.Linux_core
	var flag, sign int
	var vb, vs string
	doc.Find("tr").Each(func(i int, s *goquery.Selection) {
		var core db.Linux
		s.Find("td").Each(func(cellIdx int, cellEle *goquery.Selection) {
			band := cellEle.Text()
			if strings.Contains(band, "CVEs fixed in") {
				vb = strings.Replace(band, "CVEs fixed in ", "", -1)
				vb = strings.Replace(vb, ":", "", -1)
				vs = "fixed"
				if strings.Contains(vb, "92") {
					sign = 1
				}
				if sign == 1 {
					vs = "unprocessed"
				}
				if edition != "4.19" {
					vs = "unprocessed"
				}
				flag = 1
			}
			if strings.Contains(band, "Outstanding") {
				vb = " "
				flag = 2
			}
			if flag == 0 {
				if strings.Contains(band, " ") == true {
					core.Package = "linux"
					core.Cve_id = strings.Replace(band[1:17], ":", "", -1)
					core.Cve_id = strings.Replace(core.Cve_id, " ", "", -1)
					core.Upstream_fixed_version = vb
					core.Status = vs
					if core.Status == "fixed" {
						core.Locale_fixed_version = vb
					}
					core.Edition = edition
					if !strings.Contains(vb, " ") {
						core.Patch_upstream = strings.Replace(band[17:58], " ", "", -1)
					}
				}
			}
			flag = 0
			if len(core.Cve_id) != 0 {
				List = append(List, &core)
			}
		})
	})
	return List, nil
}
