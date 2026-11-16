package ui

import (
	"encoding/csv"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	invitationdto "github.com/bete7512/goauth/internal/modules/invitation/handlers/dto"
)

const (
	// maxImportRows is the most invitations one import sends.
	maxImportRows = 200
	// maxImportBytes bounds the uploaded file or pasted list.
	maxImportBytes = 256 << 10
)

// importRow is one line of an invitation import and what became of it.
type importRow struct {
	Line    int
	Email   string
	Purpose string
	Sent    bool
	Problem string
}

type importPage struct {
	Rows    []importRow
	Sent    int
	Skipped int
	// Back and BackLabel lead back to the invitations page; Column names
	// the second column (purpose or role).
	Back, BackLabel, Column string
}

// importInvitations sends an invitation for every row of a CSV file or a
// pasted list: an email per line, optionally followed by a purpose. A
// header row whose first cell is "email" is skipped. Each row goes through
// the same Send as the single-invitation form, so duplicates and existing
// accounts are refused the same way; one bad row never stops the others.
func (m *UIModule) importInvitations(w http.ResponseWriter, r *http.Request) {
	service := m.invitationService()
	if service == nil {
		m.unavailable(w, r, "Invitations", "invitation")
		return
	}
	source, err := importSource(w, r)
	if err != nil {
		m.showInvitations(w, r, http.StatusUnprocessableEntity, &invitationsPage{}, err.Error())
		return
	}
	rows, err := parseImport(source, r.FormValue("purpose"))
	if err != nil {
		m.showInvitations(w, r, http.StatusUnprocessableEntity, &invitationsPage{}, err.Error())
		return
	}
	inviter := visitorFrom(r.Context()).User.ID
	page := &importPage{Rows: rows, Back: m.base + "/invitations", BackLabel: "Invitations", Column: "Purpose"}
	for i := range page.Rows {
		row := &page.Rows[i]
		if row.Problem == "" {
			request := &invitationdto.SendInvitationRequest{Email: row.Email, Purpose: row.Purpose}
			if err := request.Validate(); err != nil {
				row.Problem = err.Error()
			} else if _, authErr := service.Send(r.Context(), request, inviter); authErr != nil {
				row.Problem = authErr.Message
			} else {
				row.Sent = true
			}
		}
		if row.Sent {
			page.Sent++
		} else {
			page.Skipped++
		}
	}
	m.render(w, r, http.StatusOK, "invitations_import", m.newView(r, "Invitation import", "invitations", page))
}

// importSource returns the uploaded file, or the pasted list when no file
// was chosen.
func importSource(w http.ResponseWriter, r *http.Request) (io.Reader, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxImportBytes+64<<10)
	if err := r.ParseMultipartForm(maxImportBytes); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		return nil, importProblem("The file is too large or could not be read. Import at most " + strconv.Itoa(maxImportRows) + " rows at a time.")
	}
	if r.MultipartForm != nil {
		if files := r.MultipartForm.File["file"]; len(files) > 0 && files[0].Size > 0 {
			if files[0].Size > maxImportBytes {
				return nil, importProblem("The file is too large.")
			}
			file, err := files[0].Open()
			if err != nil {
				return nil, importProblem("The file could not be read.")
			}
			return file, nil
		}
	}
	pasted := strings.TrimSpace(r.FormValue("emails"))
	if pasted == "" {
		return nil, importProblem("Choose a CSV file or paste a list of email addresses.")
	}
	return strings.NewReader(pasted), nil
}

// parseImport reads rows of email[,purpose] (or email[,role] for an
// organization). defaultPurpose fills rows without one. Repeated addresses are reported, not sent twice.
func parseImport(source io.Reader, defaultPurpose string) ([]importRow, error) {
	reader := csv.NewReader(source)
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	reader.ReuseRecord = true
	defaultPurpose = strings.TrimSpace(defaultPurpose)

	var rows []importRow
	seen := map[string]int{}
	for line := 1; ; line++ {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, importProblem("Line " + strconv.Itoa(line) + " is not valid CSV.")
		}
		email := ""
		if len(record) > 0 {
			email = strings.TrimSpace(strings.TrimPrefix(record[0], "\ufeff"))
		}
		if email == "" {
			continue
		}
		if line == 1 && strings.EqualFold(email, "email") {
			continue
		}
		if len(rows) == maxImportRows {
			return nil, importProblem("Import at most " + strconv.Itoa(maxImportRows) + " invitations at a time.")
		}
		row := importRow{Line: line, Email: email, Purpose: defaultPurpose}
		if len(record) > 1 && strings.TrimSpace(record[1]) != "" {
			row.Purpose = strings.TrimSpace(record[1])
		}
		key := strings.ToLower(email)
		if first, dup := seen[key]; dup {
			row.Problem = "Repeats line " + strconv.Itoa(first) + "."
		} else {
			seen[key] = line
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return nil, importProblem("The list has no email addresses.")
	}
	return rows, nil
}

// importProblem is a sentence about an import shown to the administrator
// as is.
type importProblem string

func (p importProblem) Error() string { return string(p) }
