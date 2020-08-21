package db

import (
	"fmt"
	"time"
)

const (
	// CVE status available values
	CVEStatusUnprocessed = "unprocessed" // 未处理
	CVEStatusProcessing  = "processing"  // 处理中
	CVEStatusPostpone    = "postpone"    // 延后
	CVEStatusHold        = "hold"        // 搁置
	CVEStatusCanceled    = "canceled"    // 取消
	CVEStatusFixed       = "fixed"       // 完成
)

// INDEX storage update time and creation time
type INDEX struct {
	//	ID        uint       `json:"-"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"-"`
}

// CVE store cve bug for tracking
type CVE struct {
	Cve_id         string  `gorm:"primary_key" json:"cve_id"`
	Package        string  `json:"package"`
	Effect         string  `json:"effect"`
	Status         string  `json:"status"`
	Description    string  `json:"description"`
	Cvss           int     `json:"cvss"`
	Pre_installed  bool    `json:"pre_installed"`
	Fixed_version  string  `json:"fixed_version"`
	Scope          string  `json:"scope"`
	Patch_local    string  `json:"patch_local"`
	Patch_upstream string  `json:"patch_upstream"`
	Poc            string  `json:"poc"`
	Score          float64 `json:"score"`
	INDEX
}

//Processing level
type Level struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}

//Processing status
type Total struct {
	Unprocessed Level `json:"unprocessed"`
	Processing  Level `json:"processing"`
	Postpone    Level `json:"postpone"`
	Hold        Level `json:"hold"`
	Canceled    Level `json:"canceled"`
	Fixed       Level `json:"fixed"`
}

func (CVE) TableName() string {
	return "dist-cve"
}

// CVEList an array for CVE
type CVEList []*CVE

// FixPackage fill package
func (list CVEList) FixPackage() {
	var prev string
	for _, cve := range list {
		if len(cve.Package) != 0 {
			prev = cve.Package
		} else {
			cve.Package = prev
		}
	}
}

func (list CVEList) Dump() {
	fmt.Println("\n--------- DUMP --------")
	for _, cve := range list {
		fmt.Println(cve.Package, cve.Cve_id)
	}
	fmt.Println("--------- DUMP END --------")
}

// Create insert cve record, if exists, ignore
func (list CVEList) Create(version string) error {
	handler := GetDBHandler(version)
	if handler == nil {
		return fmt.Errorf("Not found db hander for version '%s'", version)
	}
	var tx = handler.Begin()

	for _, cve := range list {
		var info CVE
		tx.Where("`cve_id` = ?", cve.Cve_id).First(&info)
		if info.Cve_id == cve.Cve_id {
			// exists
			continue
		}
		err := tx.Create(cve).Error
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit().Error
}

// Save save cve info
func (cve *CVE) Save(version string) error {
	handler := GetDBHandler(version)
	if handler == nil {
		return fmt.Errorf("Not found db hander for version '%s'", version)
	}
	return handler.Save(cve).Error
}

// NewCVE query cve by id
func NewCVE(id, version string) (*CVE, error) {
	handler := GetDBHandler(version)
	if handler == nil {
		return nil, fmt.Errorf("Not found db hander for version '%s'", version)
	}

	var cve CVE
	fmt.Println(id)
	err := handler.Table(("dist-cve")).Where("`cve_id` = ?", id).First(&cve).Error //修改
	if err != nil {
		return nil, err
	}
	return &cve, nil
}

//Total
func NewTotal(version string) (*Total, error) {
	handler := GetDBHandler(version)
	if handler == nil {
		return nil, fmt.Errorf("Not found db hander for version '%s'", version)
	}

	var totallist Total
	handler.Table(("dist-cve")).Where("`score` <= 4 and `status` = ?", "unprocessed").Count(&totallist.Unprocessed.Low)
	handler.Table(("dist-cve")).Where("`score` > 4 and `score` < 7 and `status` = ? ", "unprocessed").Count(&totallist.Unprocessed.Medium)
	handler.Table(("dist-cve")).Where("`score` >= 7 and `status` = ? ", "unprocessed").Count(&totallist.Unprocessed.High)

	handler.Table(("dist-cve")).Where("`score` <= 4 and `status` = ?", "processing").Count(&totallist.Processing.Low)
	handler.Table(("dist-cve")).Where("`score` > 4 and `score` < 7 and `status` = ? ", "processing").Count(&totallist.Processing.Medium)
	handler.Table(("dist-cve")).Where("`score` >= 7 and `status` = ? ", "processing").Count(&totallist.Processing.High)

	handler.Table(("dist-cve")).Where("`score` <= 4 and `status` = ?", "postpone").Count(&totallist.Postpone.Low)
	handler.Table(("dist-cve")).Where("`score` > 4 and `score` < 7 and `status` = ? ", "postpone").Count(&totallist.Postpone.Medium)
	handler.Table(("dist-cve")).Where("`score` >= 7 and `status` = ? ", "postpone").Count(&totallist.Postpone.High)

	handler.Table(("dist-cve")).Where("`score` <= 4 and `status` = ?", "hold").Count(&totallist.Hold.Low)
	handler.Table(("dist-cve")).Where("`score` > 4 and `score` < 7 and `status` = ? ", "hold").Count(&totallist.Hold.Medium)
	handler.Table(("dist-cve")).Where("`score` >= 7 and `status` = ? ", "hold").Count(&totallist.Hold.High)

	handler.Table(("dist-cve")).Where("`score` <= 4 and `status` = ?", "canceled").Count(&totallist.Canceled.Low)
	handler.Table(("dist-cve")).Where("`score` > 4 and `score` < 7 and `status` = ? ", "canceled").Count(&totallist.Canceled.Medium)
	handler.Table(("dist-cve")).Where("`score` >= 7 and `status` = ? ", "canceled").Count(&totallist.Canceled.High)

	handler.Table(("dist-cve")).Where("`score` <= 4 and `status` = ?", "fixed").Count(&totallist.Fixed.Low)
	handler.Table(("dist-cve")).Where("`score` > 4 and `score` < 7 and `status` = ? ", "fixed").Count(&totallist.Fixed.Medium)
	handler.Table(("dist-cve")).Where("`score` >= 7 and `status` = ? ", "fixed").Count(&totallist.Fixed.High)

	return &totallist, nil
}

// UpdateCVE update cve info with values
func (cve *CVE) Update(diff map[string]interface{}, version string) error {
	handler := GetDBHandler(version)
	if handler == nil {
		return fmt.Errorf("Not found db hander for version '%s'", version)
	}
	return handler.Model(cve).Updates(diff).Error
}

// ValidStatus validity status whether right
func ValidStatus(status string) bool {
	switch status {
	case CVEStatusUnprocessed, CVEStatusProcessing, CVEStatusPostpone, CVEStatusHold,
		CVEStatusFixed, CVEStatusCanceled:
		return true
	}
	return false
}

// ValidColumn validity cve table whether has this column name
func ValidColumn(name string) bool {
	switch name {
	case "id", "package", "urgency", "remote", "status", "patch", "description",
		"pre_installed", "archived", "cvss", "score", "created_at", "updated_at":
		return true
	}
	return false
}
