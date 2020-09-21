package v0

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/deepin-cve/tracker/pkg/db"
	"github.com/deepin-cve/tracker/pkg/fetcher"
	"github.com/gin-gonic/gin"
)

const (
	nvdPrefix       = "https://nvd.nist.gov/vuln/detail/"
	linuxkernelcves = "https://github.com/nluedtke/linux_kernel_cves/blob/master/data/"
)

func fetchDebian(c *gin.Context) {
	version := c.Param("version")
	if len(version) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid version",
		})
		return
	}
	var verInfo = db.Version{Version: version}
	err := verInfo.Get()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	var body = struct {
		Filters []string `json:"filters"`
	}{}
	err = c.ShouldBindJSON(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	infos, err := fetcher.Fetch(verInfo.ReleaseURL, body.Filters)
	fmt.Println(body.Filters)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	go func(cveList db.CVEList) {
		var list db.CVEList
		var scoreList db.CVEScoreList
		fmt.Println("Debian cve len:", len(cveList))
		for _, info := range cveList {
			if len(list) == 100 {
				err := list.Create(version)
				if err != nil {
					fmt.Println("Failed to create cve:", err)
					return
				}
				list = db.CVEList{}
			}
			var cve = db.CVE{
				//				DebianCVE:    *info,
				Cve_id:        info.Cve_id,
				Package:       info.Package,
				Status:        db.CVEStatusUnprocessed,
				Pre_installed: db.IsSourceExists(info.Package, version),
			}
			list = append(list, &cve)

			if len(scoreList) == 100 {
				err := scoreList.UpdateCVE(version)
				if err != nil {
					fmt.Println("Failed to update cve score list")
					return
				}
				scoreList = db.CVEScoreList{}
			}
			score, err := fecthNVDScore(info.Cve_id)
			if err != nil || score == nil {
				continue
			}
			scoreList = append(scoreList, score)
		}
		if len(list) != 0 {
			err := list.Create(version)
			if err != nil {
				fmt.Println("Failed to create cve:", err)
				return
			}
		}
		if len(scoreList) != 0 {
			err := scoreList.UpdateCVE(version)
			if err != nil {
				fmt.Println("Failed to update cve score list")
				return
			}
		}
		fmt.Println("Insert debian cve done:", body.Filters)
	}(infos)

	insertLog(&db.Log{
		Operator:    c.GetString("username"),
		Action:      db.LogActionFecthDebian,
		Description: strings.Join(body.Filters, ","),
		Content:     toString(&body),
	})

	c.String(http.StatusAccepted, "")
}

func fetchLinux(c *gin.Context) {
	var params = make(map[string]interface{})
	version := c.Param("version")
	if len(version) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid version",
		})
		return
	}
	var verInfo = db.Version{Version: version}
	err := verInfo.Get()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	edition := c.Query("edition")
	if len(edition) != 0 {
		params["edition"] = edition
	}
	go func(edition string) {
		infos, err := fetcher.Fetch_linux(linuxkernelcves, edition)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		handler := db.GetDBHandler(version)
		for i := 0; i < len(infos); i++ {
			infos[i].Score, infos[i].Cvss, _ = fecthNVDCore(infos[i].Cve_id)
			handler.Save(&infos[i])
		}
	}(edition)
	insertLog(&db.Log{
		Operator:    c.GetString("username"),
		Action:      db.LogActionFecthDebian,
		Description: "update linux list",
		Content:     c.GetString("username"),
	})
	c.String(http.StatusAccepted, "")
}

/*func initPackages(c *gin.Context) {
	version := c.Param("version")
	if len(version) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid version",
		})
		return
	}
	var verInfo = db.Version{Version: version}
	err := verInfo.Get()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	pkgHeader, err := c.FormFile("packages")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	var uploadFile = filepath.Join(config.GetConfig("").DBDir, "packages_"+version+"_"+string(db.GenToken()))
	err = c.SaveUploadedFile(pkgHeader, uploadFile)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	go func() {
		fmt.Println("Start to insert packages")
		err := packages.ImportPackage(uploadFile, version)
		if err != nil {
			fmt.Println("Failed to import packages:", err)
		}
		fmt.Println("Start to insert packages done")
	}()

	insertLog(&db.Log{
		Operator:    c.GetString("username"),
		Action:      db.LogActionInitPackage,
		Description: db.LogActionInitPackage.String(),
		Content:     "init package version: " + version + ", file: " + uploadFile,
	})

	c.String(http.StatusAccepted, "")
}*/

func fetchScore(c *gin.Context) {
	version := c.Param("version")
	if len(version) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid version",
		})
		return
	}
	var verInfo = db.Version{Version: version}
	err := verInfo.Get()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	go func(v string) {
		fmt.Println("[Debug] start to fetch cve score")
		var (
			length = 100
			limit  = 100
			offset = 0

			scoreList = db.CVEScoreList{}

			handler = db.GetDBHandler(v)
		)
		for length == limit {
			if len(scoreList) >= 100 {
				err := scoreList.UpdateCVE(v)
				if err != nil {
					fmt.Println("Failed to update cve score:", err)
					return
				}
				scoreList = db.CVEScoreList{}
			}

			var cveList db.CVEList
			handler.Offset(offset).Limit(limit).Find(&cveList)
			length = len(cveList)
			offset += length

			for _, info := range cveList {
				if info.Score > 0 {
					continue
				}
				score, err := fecthNVDScore(info.Cve_id)
				if err != nil || score == nil {
					continue
				}
				scoreList = append(scoreList, score)
			}
		}

		if len(scoreList) == 0 {
			fmt.Println("[Debug] fetch cve score done")
			return
		}
		err := scoreList.UpdateCVE(v)
		if err != nil {
			fmt.Println("Failed to update cve score:", err)
			return
		}
		fmt.Println("[Debug] fetch cve score done")
	}(version)

	insertLog(&db.Log{
		Operator:    c.GetString("username"),
		Action:      db.LogActionFetchScore,
		Description: db.LogActionFetchScore.String(),
		Content:     "fetch score version: " + version,
	})

	c.String(http.StatusAccepted, "")
}

func fecthNVDScore(id string) (*db.CVEScore, error) {
	if !strings.Contains(id, "CVE") {
		return nil, nil
	}
	score, err := fetcher.FetchScore(nvdPrefix + id)
	if err != nil {
		fmt.Println("Failed to fetch cve score:", err, id)
		return nil, err
	}
	return score, nil
}

func fecthNVDCore(id string) (float64, int, error) {
	res, err := http.Get(nvdPrefix + id)
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
	var vb string
	var score float64
	cvss := 1
	var flag int
	doc.Find("span").Each(func(i int, s *goquery.Selection) {
		s.Find("span").Each(func(cellIdx int, cellEle *goquery.Selection) {
			band := cellEle.Find("a").Text()
			if strings.Contains(band, "HIGH") || strings.Contains(band, "MEDIUM") || strings.Contains(band, "CRITICAL") || strings.Contains(band, "LOW") {
				cvss += 1
				if flag == 0 {
					vb = strings.Replace(band[:4], " ", "", -1)
					score, _ = strconv.ParseFloat(vb, 64)
					flag = 1
				}
			}
		})
	})
	if cvss >= 4 {
		cvss = 3
	} else if cvss == 1 {
		cvss = 0
	}
	return score, cvss, nil
}
