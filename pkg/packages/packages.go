package packages

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/deepin-cve/tracker/pkg/db"
)

var (
	_importStat   bool
	_importLocker sync.Mutex
)

func isImportPackage() bool {
	_importLocker.Lock()
	stat := _importStat
	_importLocker.Unlock()
	return stat
}

func setImportStat(v bool) {
	_importLocker.Lock()
	_importStat = v
	_importLocker.Unlock()
}

// ImportPackage import packages in ISO Image
// The filename generated by the command "dpkg-query -f '${Package},${Architecture},${Version},${Source}\n'"
func ImportPackage(filename string) error {
	if isImportPackage() {
		return fmt.Errorf("There has a packages importer running, try later")
	}
	setImportStat(true)
	defer setImportStat(false)

	// clear packages table records
	err := db.PkgDB.Delete(&db.Package{}).Error
	if err != nil {
		return err
	}

	fr, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fr.Close()

	var scanner = bufio.NewScanner(fr)

	var infos db.PackageList
	for scanner.Scan() {
		if len(infos) == 100 {
			err = infos.Create()
			if err != nil {
				return err
			}
			// empty
			infos = db.PackageList{}
		}

		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		items := strings.Split(line, ",")
		if len(items) != 4 {
			fmt.Println("invalid output line:", line)
			continue
		}
		var info = db.Package{
			Package:      items[0] + ":" + items[1],
			Architecture: items[1],
			Version:      items[2],
		}
		tmp := strings.SplitN(items[3], " ", 2)
		info.Source = tmp[0]
		if len(tmp) == 2 {
			info.SourceVersion = strings.TrimLeft(tmp[1], "(")
			info.SourceVersion = strings.TrimRight(info.SourceVersion, ")")
		}
		infos = append(infos, &info)
	}

	if len(infos) == 0 {
		return nil
	}

	return infos.Create()
}