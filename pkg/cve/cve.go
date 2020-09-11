package cve

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/deepin-cve/tracker/pkg/db"
	"github.com/jinzhu/gorm"
)

// QueryCVEList query by filter
// TODO(jouyouyun): add scope filter supported
func QueryCVEList(params map[string]interface{}, offset, count int,
	version string) (db.CVEList, int64, error) {
	handler := db.GetDBHandler(version)
	if handler == nil {
		return nil, 0, fmt.Errorf("No db handler found for version '%s'", version)
	}
	var sql = handler.Table(("dist-cve")) //直接连接dist-cve
	sql = addParamsToSQL(sql, params)

	value, ok := params["sort"]
	if ok {
		sort, ok := value.(string)
		if ok && len(sort) != 0 {
			var order string
			if sort == "updated_at" || sort == "score" {
				order = " desc"
			}
			sql = sql.Order(fmt.Sprintf("%s%s", sort, order))
		}
	} else {
		// default
		sql = sql.Order("score desc")
	}
	//sql = sql.Where("package != ? and package != ?","linux","webkit2gtk")

	var list db.CVEList
	var total int64
	sql.Count(&total)
	err := sql.Offset(offset).Limit(count).Find(&list).Error
	if err != nil {
		return nil, 0, err
	}

	return list, total, nil
}

func QueryUPList(params map[string]interface{}, offset, count int,
	version string) (db.UPList, int64, error) {
	handler := db.GetDBHandler(version)
	if handler == nil {
		return nil, 0, fmt.Errorf("No db handler found for version '%s'", version)
	}
	var sql = handler.Table(("upstream"))
	//	sql = addParamsToSQL(sql, params)
	var availableList = []struct {
		key     string
		useLike bool
	}{
		{"package", true},
		{"cve_id", true},
		{"status", false},
	}
	for _, item := range availableList {
		if v, ok := params[item.key]; ok {
			compare := "="
			if item.useLike {
				compare = "LIKE"
			}
			sql = sql.Where(fmt.Sprintf("`%s` %s ?", item.key, compare), v)
		}
	}
	var up db.UPList
	var total int64
	sql.Count(&total)
	err := sql.Offset(offset).Limit(count).Find(&up).Error
	if err != nil {
		return nil, 0, err
	}
	return up, total, nil
}

func QueryLinuxList(params map[string]interface{}, offset, count int,
	version string) (db.Linux_core, int64, error) {
	handler := db.GetDBHandler(version)
	if handler == nil {
		return nil, 0, fmt.Errorf("No db handler found for version '%s'", version)
	}
	var sql = handler.Table(("linux"))
	var availableList = []struct {
		key     string
		useLike bool
	}{
		{"edition", true},
		{"cve_id", true},
		{"status", false},
	}
	value, ok := params["sort"]
	if ok {
		sort, ok := value.(string)
		if ok && len(sort) != 0 {
			var order string
			if sort == "updated_at" || sort == "score" {
				order = " desc"
			}
			sql = sql.Order(fmt.Sprintf("%s%s", sort, order))
		}
	} else {
		// default
		sql = sql.Order("score desc")
	}
	for _, item := range availableList {
		if v, ok := params[item.key]; ok {
			compare := "="
			if item.useLike {
				compare = "LIKE"
			}
			sql = sql.Where(fmt.Sprintf("`%s` %s ?", item.key, compare), v)
		}
	}
	score, ok := params["score"]
	if ok {
		scoreParam := strings.Split(score.(string), "-")
		scoreone, _ := strconv.Atoi(scoreParam[0])
		if len(scoreParam) == 1 {
			sql = sql.Where("score = ? ", scoreone)
		} else if len(scoreParam) == 2 {
			scoretwo, _ := strconv.Atoi(scoreParam[1])
			if scoreone > scoretwo {
				scoreone, scoretwo = scoretwo, scoreone
			}
			sql = sql.Where("score >= ? and score <= ?", scoreone, scoretwo)
		}
	}
	var linux db.Linux_core
	var total int64
	sql.Count(&total)
	err := sql.Offset(offset).Limit(count).Find(&linux).Error
	if err != nil {
		return nil, 0, err
	}
	return linux, total, nil
}

// UpdateCVE modify cve info
func UpdateCVE(id, version string, values map[string]interface{}) (*db.CVE, error) {
	cve, err := db.NewCVE(id, version)
	if err != nil {
		return nil, err
	}

	err = cve.Update(values, version)
	if err != nil {
		return nil, err
	}
	return cve, nil
}

func UpdateLinux(edition, id, version string, values map[string]interface{}) (*db.Linux, error) {
	linux, err := db.NewLinux(edition, id, version)
	if err != nil {
		return nil, err
	}

	err = linux.Update(values, version)
	if err != nil {
		return nil, err
	}
	return linux, nil
}

func addParamsToSQL(sql *gorm.DB, params map[string]interface{}) *gorm.DB {
	if len(params) == 0 {
		return sql
	}
	score, ok := params["score"]
	if ok {
		scoreParam := strings.Split(score.(string), "-")
		scoreone, _ := strconv.Atoi(scoreParam[0])
		if len(scoreParam) == 1 {
			sql = sql.Where("score = ? ", scoreone)
		} else if len(scoreParam) == 2 {
			scoretwo, _ := strconv.Atoi(scoreParam[1])
			if scoreone > scoretwo {
				scoreone, scoretwo = scoretwo, scoreone
			}
			sql = sql.Where("score >= ? and score <= ?", scoreone, scoretwo)
		}
	}
	ex_pkg, ok := params["ex_pkg"]
	if ok && ex_pkg.(string) == "true" {
		sql = sql.Where("package != ?", "linux")
	}
	var availableList = []struct {
		key     string
		useLike bool
	}{
		{"package", true},
		{"effect", true}, //影响范围
		{"pre_installed", false},
	}

	for _, item := range availableList {
		if v, ok := params[item.key]; ok {
			compare := "="
			if item.useLike {
				compare = "LIKE"
			}
			sql = sql.Where(fmt.Sprintf("`%s` %s ?", item.key, compare), v)
		}
	}
	return addListParamsToSQL(sql, params)
}

func addListParamsToSQL(sql *gorm.DB, params map[string]interface{}) *gorm.DB {
	var availableList = []struct {
		key    string
		column string
	}{
		{"status", "status"},
	}
	for _, info := range availableList {
		values, ok := params[info.key]
		if !ok {
			continue
		}
		list, ok := values.([]string)
		if !ok {
			continue
		}
		if len(list) != 0 {
			col := fmt.Sprintf("`%s` = ?", info.column)
			sql = sql.Where(col, list[0])
			for i := 1; i < len(list); i++ {
				sql = sql.Or(col, list[i])
			}
		}
	}
	return sql
}
