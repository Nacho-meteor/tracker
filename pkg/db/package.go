package db

import (
	"fmt"
)

//Pre-installed
type PrePackage struct {
	Id          int    `gorm:"primary_key" json:"id"` //  unique key
	Name        string `json:"name"`
	Source_name string `json:"source_name"`
}

type PrePackageList []*PrePackage

func (PrePackageList) TableName() string {
	return "packages"
}

type Package struct {
	Id            int `gorm:"primary_key" json:"id"` //  unique key
	Dist_id       int `json:"dist_id"`
	Package_id    int `json:"package_id"`
	Pre_installed int `json:"pre_installed"`
}

func (Package) TableName() string {
	return "dist-packages"
}

// PackageList package list
type PackageList []*Package

// NrePackage query package from db
func NewPackage(pkg, arch, dbVersion string) (*Package, error) {
	if len(pkg) == 0 || len(arch) == 0 {
		return nil, fmt.Errorf("invalid package(%q) or architecture(%q)",
			pkg, arch)
	}

	handler := GetDBHandler(dbVersion)
	if handler == nil {
		return nil, fmt.Errorf("Not found db hander for version '%s'", dbVersion)
	}

	var info Package
	err := handler.Where("`package` = ? AND `architecture` = ?",
		pkg, arch).First(&info).Error
	if err != nil {
		return nil, err
	}
	return &info, nil
}

// IsSourceExists query whether source exists
func IsSourceExists(source, dbVersion string) bool {
	if len(source) == 0 {
		return false
	}

	handler := GetDBHandler(dbVersion)
	if handler == nil {
		return false
	}

	//var infos PackageList
	var preinfo PrePackageList
	err := handler.Model(&PrePackage{}).Where("`source_name` = ?", source).Find(&preinfo).Error
	//err := handler.Model(&Package{}).Where("`source` = ?", source).Find(&infos).Error 
	if err != nil {
		return false
	}
	if len(preinfo) == 0 {
		return false
	}
	return true
}

// Create insert package list
func (infos PackageList) Create(dbVersion string) error {
	handler := GetDBHandler(dbVersion)
	if handler == nil {
		return fmt.Errorf("Not found db hander for version '%s'", dbVersion)
	}

	var tx = handler.Begin()
	for _, info := range infos {
		err := tx.Model(&Package{}).Create(info).Error
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit().Error
}
