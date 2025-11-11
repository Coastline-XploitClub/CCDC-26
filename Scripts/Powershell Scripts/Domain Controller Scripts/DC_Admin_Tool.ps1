Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#================ GLOBAL VARIABLES ================#
$Global:DCIP = ""
$Global:DomainName = ""
$Global:AdminCredential = $null
$Global:UserTable = $null

#================ FUNCTIONS ================#

function Change-UserPassword {
    param($DC, $TargetUser, $NewPw)
    try {
        if (-not $Global:AdminCredential) {
            throw "Admin credential not set. Please save credentials first."
        }

        Invoke-Command -ComputerName $DC -Credential $Global:AdminCredential -ScriptBlock {
            param($User, $Pw)
            try {
                net user $User $Pw /domain
                "Password for user '$User' changed successfully."
            } catch {
                "Failed to change password for '$User': $($_.Exception.Message)"
            }
        } -ArgumentList $TargetUser, $NewPw -ErrorAction Stop

    } catch {
        return "Error changing password: $($_.Exception.Message)"
    }
}

function Create-AdminUser {
    param($DC, $NewUser, $NewPw)
    try {
        if (-not $Global:AdminCredential) {
            throw "Admin credential not set. Please save credentials first."
        }

        $result = Invoke-Command -ComputerName $DC -Credential $Global:AdminCredential -ScriptBlock {
            param($u, $p)
            try {
                net user $u $p /add /y | Out-Null
                net localgroup Administrators $u /add | Out-Null
                net group "Domain Admins" $u /add | Out-Null
                "User '$u' successfully created and added to Domain Admins."
            } catch {
                "Failed to create user '$u': $($_.Exception.Message)"
            }
        } -ArgumentList $NewUser, $NewPw -ErrorAction Stop

        return $result
    } catch {
        return "Error creating admin: $($_.Exception.Message)"
    }
}
function Disable-UserAccount {
    param($DC, $TargetUser)
    try {
        if (-not $Global:AdminCredential) {
            throw "Admin credential not set. Please save credentials first."
        }

        Invoke-Command -ComputerName $DC -Credential $Global:AdminCredential -ScriptBlock {
            param($User)
            try {
                net user $User /active:no /domain
                "Account '$User' has been disabled successfully."
            } catch {
                "Failed to disable account '$User': $($_.Exception.Message)"
            }
        } -ArgumentList $TargetUser -ErrorAction Stop
    }
    catch {
        return "Error disabling account: $($_.Exception.Message)"
    }
}

function Enable-UserAccount {
    param($DC, $TargetUser)
    try {
        if (-not $Global:AdminCredential) {
            throw "Admin credential not set. Please save credentials first."
        }

        $result = Invoke-Command -ComputerName $DC -Credential $Global:AdminCredential -ScriptBlock {
            param($u)
            try {
                # Enable in AD (not local)
                net user $u /active:yes /domain | Out-Null
                "Account '$u' enabled successfully in the domain."
            } catch {
                "Error enabling account '$u': $($_.Exception.Message)"
            }
        } -ArgumentList $TargetUser -ErrorAction Stop

        return $result
    } catch {
        return "Failed to enable account: $($_.Exception.Message)"
    }
}

function Get-ADUsersList {
    param($DC)

    try {
        if (-not $Global:AdminCredential) {
            throw "Admin credential not set. Please save credentials first."
        }

        $result = Invoke-Command -ComputerName $DC -Credential $Global:AdminCredential -ScriptBlock {
            try {
                # Pull user info (use dsquery alternative for no AD module)
                $users = Get-WmiObject -Class Win32_UserAccount -Filter "Domain='$env:USERDOMAIN'"
                $users | Select-Object Name, Disabled, LocalAccount, SID
            } catch {
                "Failed to get users: $($_.Exception.Message)"
            }
        } -ErrorAction Stop

        return $result
    }
    catch {
        return "Error retrieving users: $($_.Exception.Message)"
    }
}


#================ GUI ================#

$form = New-Object System.Windows.Forms.Form
$form.Text = "Coastline Xploit Club => Domain Controller Admin Toolkit (Secure)"
$form.Size = New-Object System.Drawing.Size(800,600)
$form.MaximizeBox = $false
$form.FormBorderStyle = 'FixedDialog'

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Size = New-Object System.Drawing.Size(780,500)
$tabs.Location = New-Object System.Drawing.Point(10,10)

# Output Log
$txtOutput = New-Object System.Windows.Forms.TextBox
$txtOutput.Multiline = $true
$txtOutput.ScrollBars = "Vertical"
$txtOutput.Size = New-Object System.Drawing.Size(760,60)
$txtOutput.Location = New-Object System.Drawing.Point(10,520)
$txtOutput.ReadOnly = $true
$txtOutput.BackColor = [System.Drawing.Color]::WhiteSmoke

#================ CONNECTION TAB ================#
$tabConn = New-Object System.Windows.Forms.TabPage
$tabConn.Text = "Connection"

# Label & text alignment — slightly more vertical space and AutoSize
$lblDC = New-Object System.Windows.Forms.Label
$lblDC.Text = "Domain Controller IP:"
$lblDC.Location = New-Object System.Drawing.Point(20, 25)
$lblDC.AutoSize = $true

$txtDC = New-Object System.Windows.Forms.TextBox
$txtDC.Location = New-Object System.Drawing.Point(200, 22)
$txtDC.Size = New-Object System.Drawing.Size(220, 22)

$lblDomain = New-Object System.Windows.Forms.Label
$lblDomain.Text = "Domain Name:"
$lblDomain.Location = New-Object System.Drawing.Point(20, 70)
$lblDomain.AutoSize = $true

$txtDomain = New-Object System.Windows.Forms.TextBox
$txtDomain.Location = New-Object System.Drawing.Point(200, 67)
$txtDomain.Size = New-Object System.Drawing.Size(220, 22)

$lblUser = New-Object System.Windows.Forms.Label
$lblUser.Text = "Admin Username:"
$lblUser.Location = New-Object System.Drawing.Point(20, 115)
$lblUser.AutoSize = $true

$txtUser = New-Object System.Windows.Forms.TextBox
$txtUser.Location = New-Object System.Drawing.Point(200, 112)
$txtUser.Size = New-Object System.Drawing.Size(220, 22)

$lblPw = New-Object System.Windows.Forms.Label
$lblPw.Text = "Admin Password:"
$lblPw.Location = New-Object System.Drawing.Point(20, 160)
$lblPw.AutoSize = $true

$txtPw = New-Object System.Windows.Forms.TextBox
$txtPw.Location = New-Object System.Drawing.Point(200, 157)
$txtPw.Size = New-Object System.Drawing.Size(220, 22)
$txtPw.UseSystemPasswordChar = $true

# Buttons 
$btnSaveConn = New-Object System.Windows.Forms.Button
$btnSaveConn.Text = "Save Connection"
$btnSaveConn.Location = New-Object System.Drawing.Point(20, 200)
$btnSaveConn.Add_Click({
    $Global:DCIP = $txtDC.Text.Trim()
    $Global:DomainName = $txtDomain.Text.Trim()
    $txtOutput.AppendText("Connection info saved: DC=$($Global:DCIP), Domain=$($Global:DomainName)`r`n")
})

$btnTestConn = New-Object System.Windows.Forms.Button
$btnTestConn.Text = "Test Connection"
$btnTestConn.Location = New-Object System.Drawing.Point(160, 200)
$btnTestConn.Add_Click({
    try {
        $dcIP = $txtDC.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($dcIP)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter a valid Domain Controller IP first.","Input Error","Ok","Error")
            return
        }
        if (Test-Connection -ComputerName $dcIP -Count 1 -Quiet) {
            [System.Windows.Forms.MessageBox]::Show("Successfully connected to $dcIP","Connection Success","Ok","Information")
        } else {
            [System.Windows.Forms.MessageBox]::Show("Failed to connect to $dcIP","Connection Failed","Ok","Error")
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error testing connection: $($_.Exception.Message)","Connection Test Error","Ok","Error")
    }
})

$btnSaveCred = New-Object System.Windows.Forms.Button
$btnSaveCred.Text = "Save Admin Credential"
$btnSaveCred.Location = New-Object System.Drawing.Point(320, 200)
$btnSaveCred.Add_Click({
    try {
        $user = $txtUser.Text.Trim()
        $pw = $txtPw.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($user) -or [string]::IsNullOrWhiteSpace($pw)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter both username and password.","Error","OK","Error")
            return
        }
        $secPw = ConvertTo-SecureString $pw -AsPlainText -Force
        $Global:AdminCredential = New-Object System.Management.Automation.PSCredential($user, $secPw)
        $txtPw.Text = ""
        [System.Windows.Forms.MessageBox]::Show("Credential saved securely for $user.","Saved","OK","Information")
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error saving credential: $($_.Exception.Message)","Error","OK","Error")
    }
})

$tabConn.Controls.AddRange(@(
    $lblDC,$txtDC,$lblDomain,$txtDomain,
    $lblUser,$txtUser,$lblPw,$txtPw,
    $btnSaveConn,$btnTestConn,$btnSaveCred
))


#================ CREATE ADMIN USER TAB ================#
$tabCreate = New-Object System.Windows.Forms.TabPage
$tabCreate.Text = "Create Admin User"

# --- New Admin Username ---
$lblNewUser = New-Object System.Windows.Forms.Label
$lblNewUser.Text = "New Admin Username:"
$lblNewUser.Location = New-Object System.Drawing.Point(20, 25)
$lblNewUser.AutoSize = $true

$txtNewUser = New-Object System.Windows.Forms.TextBox
$txtNewUser.Location = New-Object System.Drawing.Point(200, 22)
$txtNewUser.Size = New-Object System.Drawing.Size(220, 22)

# --- New Admin Password ---
$lblNewPw = New-Object System.Windows.Forms.Label
$lblNewPw.Text = "Password for New Admin:"
$lblNewPw.Location = New-Object System.Drawing.Point(20, 70)
$lblNewPw.AutoSize = $true

$txtNewPw = New-Object System.Windows.Forms.TextBox
$txtNewPw.Location = New-Object System.Drawing.Point(200, 67)
$txtNewPw.Size = New-Object System.Drawing.Size(220, 22)
$txtNewPw.UseSystemPasswordChar = $true

# --- Button ---
$btnCreateAdmin = New-Object System.Windows.Forms.Button
$btnCreateAdmin.Text = "Create Admin Account"
$btnCreateAdmin.Location = New-Object System.Drawing.Point(20, 110)
$btnCreateAdmin.Add_Click({
    try {
        if (-not $Global:AdminCredential) {
            [System.Windows.Forms.MessageBox]::Show("Please save your domain admin credentials first on the Connection tab.","Error","OK","Error")
            return
        }

        $dc = $Global:DCIP
        $newUser = $txtNewUser.Text.Trim()
        $newPw = $txtNewPw.Text.Trim()

        if ([string]::IsNullOrWhiteSpace($newUser) -or [string]::IsNullOrWhiteSpace($newPw)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter both username and password for the new admin user.","Error","OK","Error")
            return
        }

        $result = Create-AdminUser -DC $dc -NewUser $newUser -NewPw $newPw
        [System.Windows.Forms.MessageBox]::Show($result,"Result","OK","Information")
        $txtOutput.AppendText("$result`r`n")
        $txtNewUser.Text = ""
        $txtNewPw.Text = ""

    } catch {
        $err = "Error: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show($err,"Error","OK","Error")
        $txtOutput.AppendText("$err`r`n")
    }
})

# --- Add controls to tab ---
$tabCreate.Controls.AddRange(@(
    $lblNewUser, $txtNewUser,
    $lblNewPw, $txtNewPw,
    $btnCreateAdmin
))


#================ CHANGE PASSWORD TAB ================#
$tabPw = New-Object System.Windows.Forms.TabPage
$tabPw.Text = "Change Password"

# --- Label: Target Username ---
$lblTargetUser = New-Object System.Windows.Forms.Label
$lblTargetUser.Text = "Target Username:"
$lblTargetUser.Location = New-Object System.Drawing.Point(20, 25)
$lblTargetUser.AutoSize = $true

# --- Input: Target Username ---
$txtTargetUser = New-Object System.Windows.Forms.TextBox
$txtTargetUser.Location = New-Object System.Drawing.Point(200, 22)
$txtTargetUser.Size = New-Object System.Drawing.Size(220, 22)

# --- Label: New Password ---
$lblNewPw2 = New-Object System.Windows.Forms.Label
$lblNewPw2.Text = "New Password:"
$lblNewPw2.Location = New-Object System.Drawing.Point(20, 70)
$lblNewPw2.AutoSize = $true

# --- Input: New Password ---
$txtNewPw2 = New-Object System.Windows.Forms.TextBox
$txtNewPw2.Location = New-Object System.Drawing.Point(200, 67)
$txtNewPw2.Size = New-Object System.Drawing.Size(220, 22)
$txtNewPw2.UseSystemPasswordChar = $true

# --- Label: Confirm New Password ---
$lblConfirmPw = New-Object System.Windows.Forms.Label
$lblConfirmPw.Text = "Confirm New Password:"
$lblConfirmPw.Location = New-Object System.Drawing.Point(20, 115)
$lblConfirmPw.AutoSize = $true

# --- Input: Confirm New Password ---
$txtConfirmPw = New-Object System.Windows.Forms.TextBox
$txtConfirmPw.Location = New-Object System.Drawing.Point(200, 112)
$txtConfirmPw.Size = New-Object System.Drawing.Size(220, 22)
$txtConfirmPw.UseSystemPasswordChar = $true

# --- Button: Change Password ---
$btnChangePw = New-Object System.Windows.Forms.Button
$btnChangePw.Text = "Change Password"
$btnChangePw.Location = New-Object System.Drawing.Point(20, 155)
$btnChangePw.Size = New-Object System.Drawing.Size(150, 30)

$btnChangePw.Add_Click({
    try {
        $targetUser = $txtTargetUser.Text.Trim()
        $newPw = $txtNewPw2.Text.Trim()
        $confirmPw = $txtConfirmPw.Text.Trim()

        if ([string]::IsNullOrWhiteSpace($targetUser) -or [string]::IsNullOrWhiteSpace($newPw) -or [string]::IsNullOrWhiteSpace($confirmPw)) {
            [System.Windows.Forms.MessageBox]::Show("Please fill in all fields.","Error","OK","Error")
            return
        }

        if ($newPw -ne $confirmPw) {
            [System.Windows.Forms.MessageBox]::Show("New password and confirmation do not match.","Error","OK","Error")
            return
        }

        $msg = Change-UserPassword -DC $Global:DCIP -TargetUser $targetUser -NewPw $newPw
        [System.Windows.Forms.MessageBox]::Show($msg,"Result","OK","Information")
        $txtOutput.AppendText("$msg`r`n")

        $txtTargetUser.Clear()
        $txtNewPw2.Clear()
        $txtConfirmPw.Clear()
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)","Error","OK","Error")
    }
})
#================ DISABLE ACCOUNT TAB ================#
$tabDisable = New-Object System.Windows.Forms.TabPage
$tabDisable.Text = "Disable Account"

# --- Label: Target Username ---
$lblDisableUser = New-Object System.Windows.Forms.Label
$lblDisableUser.Text = "Target Username:"
$lblDisableUser.Location = New-Object System.Drawing.Point(20, 25)
$lblDisableUser.AutoSize = $true

# --- Input: Username ---
$txtDisableUser = New-Object System.Windows.Forms.TextBox
$txtDisableUser.Location = New-Object System.Drawing.Point(200, 22)
$txtDisableUser.Size = New-Object System.Drawing.Size(220, 22)

# --- Button: Disable Account ---
$btnDisableUser = New-Object System.Windows.Forms.Button
$btnDisableUser.Text = "Disable Account"
$btnDisableUser.Location = New-Object System.Drawing.Point(20, 65)
$btnDisableUser.Size = New-Object System.Drawing.Size(150, 30)

$btnDisableUser.Add_Click({
    try {
        $targetUser = $txtDisableUser.Text.Trim()

        if ([string]::IsNullOrWhiteSpace($targetUser)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter the username to disable.","Error","OK","Error")
            return
        }

        $msg = Disable-UserAccount -DC $Global:DCIP -TargetUser $targetUser
        [System.Windows.Forms.MessageBox]::Show($msg,"Result","OK","Information")
        $txtOutput.AppendText("$msg`r`n")

        $txtDisableUser.Clear()
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)","Error","OK","Error")
    }
})

# --- Add all controls to the tab ---
$tabDisable.Controls.AddRange(@(
    $lblDisableUser,
    $txtDisableUser,
    $btnDisableUser
))




#================ USER MANAGEMENT TAB ================#
$tabUsers = New-Object System.Windows.Forms.TabPage
$tabUsers.Text = "User Management"

# --- Search label and box ---
$lblSearch = New-Object System.Windows.Forms.Label
$lblSearch.Text = "Filter by Name:"
$lblSearch.Location = New-Object System.Drawing.Point(20, 10)
$lblSearch.AutoSize = $true

$txtSearch = New-Object System.Windows.Forms.TextBox
$txtSearch.Location = New-Object System.Drawing.Point(110, 10)
$txtSearch.Size = New-Object System.Drawing.Size(140, 22)

# --- Buttons ---
$btnRefreshUsers = New-Object System.Windows.Forms.Button
$btnRefreshUsers.Text = "Get Users"
$btnRefreshUsers.Location = New-Object System.Drawing.Point(255, 10)
$btnRefreshUsers.Size = New-Object System.Drawing.Size(90, 20)


$btnEnableSelected = New-Object System.Windows.Forms.Button
$btnEnableSelected.Text = "Enable User"
$btnEnableSelected.Location = New-Object System.Drawing.Point(455, 10)
$btnEnableSelected.size = New-Object System.Drawing.Size(90, 20)

$btnDisableSelected = New-Object System.Windows.Forms.Button
$btnDisableSelected.Text = "Disable User"
$btnDisableSelected.Location = New-Object System.Drawing.Point(555, 10)
$btnDisableSelected.Size = New-Object System.Drawing.Size(90, 20)

# --- Delete Selected Button ---
$btnDeleteUser = New-Object System.Windows.Forms.Button
$btnDeleteUser.Text = "Delete User"
$btnDeleteUser.Location = New-Object System.Drawing.Point(655, 10)
$btnDeleteUser.Size = New-Object System.Drawing.Size(90, 20)

$btnDeleteUser.Add_Click({
    try {
        if (-not $Global:AdminCredential) {
            [System.Windows.Forms.MessageBox]::Show(
                "Please save your admin credentials on the Connection tab first.",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }

        $selectedRows = $gridUsers.SelectedRows
        if ($selectedRows.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "Please select at least one user to delete.",
                "No Selection",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }

        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "Are you sure you want to permanently delete the selected user(s)?",
            "Confirm Delete",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )

        if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
            foreach ($row in $selectedRows) {
                $user = $row.Cells["Username"].Value
                if (-not [string]::IsNullOrWhiteSpace($user)) {
                    try {
                        Invoke-Command -ComputerName $Global:DCIP -Credential $Global:AdminCredential -ScriptBlock {
                            param($user)
                            net user $user /delete
                        } -ArgumentList $user -ErrorAction Stop

                        $txtOutput.AppendText("User '$user' deleted successfully.`r`n")
                    }
                    catch {
                        $txtOutput.AppendText("Error deleting '$user': $($_.Exception.Message)`r`n")
                    }
                }
            }

            [System.Windows.Forms.MessageBox]::Show(
                "Selected user(s) deleted successfully.",
                "Completed",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )

            # Refresh the table automatically
            $btnRefreshUsers.PerformClick()
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Error during user deletion: $($_.Exception.Message)",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})


# --- Save to Excel Button ---
$btnExportExcel = New-Object System.Windows.Forms.Button
$btnExportExcel.Text = "Save to Excel"
$btnExportExcel.Location = New-Object System.Drawing.Point(355, 10)
$btnExportExcel.Size = New-Object System.Drawing.Size(90, 20)

$btnExportExcel.Add_Click({
    try {
        if (-not $Global:UserTable) {
            [System.Windows.Forms.MessageBox]::Show(
                "No data to export. Please refresh the list first.",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }

        # File dialog
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = "Excel Spreadsheet (*.xlsx)|*.xlsx|CSV File (*.csv)|*.csv"
        $saveDialog.Title = "Save User List"
        if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $path = $saveDialog.FileName

            # Detect format choice
            if ($path -like "*.csv") {
                # Simple CSV export
                $Global:UserTable | Export-Csv -Path $path -NoTypeInformation
            } else {
                # Full Excel export
                $excel = New-Object -ComObject Excel.Application
                $excel.Visible = $false
                $workbook = $excel.Workbooks.Add()
                $sheet = $workbook.ActiveSheet
                $sheet.Name = "Users"

                # Header
                $colIndex = 1
                foreach ($col in $Global:UserTable.Columns) {
                    $sheet.Cells.Item(1, $colIndex).Value = $col.ColumnName
                    $sheet.Cells.Item(1, $colIndex).Font.Bold = $true
                    $sheet.Cells.Item(1, $colIndex).Interior.ColorIndex = 15
                    $colIndex++
                }

                # Data
                $rowIndex = 2
                foreach ($row in $Global:UserTable.Rows) {
                    for ($i = 0; $i -lt $Global:UserTable.Columns.Count; $i++) {
                        $sheet.Cells.Item($rowIndex, $i + 1).Value = $row[$i]
                    }
                    $rowIndex++
                }

                # Auto-fit columns
                $sheet.Columns.AutoFit()
                $workbook.SaveAs($path)
                $excel.Quit()
                [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
            }

            [System.Windows.Forms.MessageBox]::Show(
                "User list exported successfully to:`n$path",
                "Export Successful",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Error exporting user list: $($_.Exception.Message)",
            "Export Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})

# --- DataGridView ---
$gridUsers = New-Object System.Windows.Forms.DataGridView
$gridUsers.Location = New-Object System.Drawing.Point(20, 80)
$gridUsers.Size = New-Object System.Drawing.Size(740, 360)
$gridUsers.ReadOnly = $true
$gridUsers.AllowUserToAddRows = $false
$gridUsers.AutoSizeColumnsMode = "Fill"
$gridUsers.SelectionMode = "FullRowSelect"
$gridUsers.BackgroundColor = [System.Drawing.Color]::WhiteSmoke


# lines for better scrolling and usability
$gridUsers.ScrollBars = [System.Windows.Forms.ScrollBars]::Both
$gridUsers.AutoGenerateColumns = $true
$gridUsers.AllowUserToDeleteRows = $false
$gridUsers.MultiSelect = $false
$gridUsers.RowHeadersVisible = $true
$gridUsers.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::DisplayedCells


# --- Load Users ---
$btnRefreshUsers.Add_Click({
    try {
        $txtOutput.AppendText("Refreshing user list...`r`n")
        $users = Get-ADUsersList -DC $Global:DCIP

        if ($users -is [string]) {
            [System.Windows.Forms.MessageBox]::Show($users,"Error","OK","Error")
            return
        }

        $table = New-Object System.Data.DataTable
        $table.Columns.Add("Username")
        $table.Columns.Add("Disabled")
        $table.Columns.Add("SID")

        foreach ($u in $users) {
            $row = $table.NewRow()
            $row["Username"] = $u.Name
            $row["Disabled"] = $u.Disabled
            $row["SID"] = $u.SID
            $table.Rows.Add($row)
        }

        $Global:UserTable = $table   # ✅ Cache the table
        $gridUsers.DataSource = $Global:UserTable
        $txtOutput.AppendText("User list loaded successfully.`r`n")
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error loading users: $($_.Exception.Message)","Error","OK","Error")
    }
})


# --- Search Filter (real-time, includes first key typed) ---
$txtSearch.Add_TextChanged({
    try {
        # Use BeginInvoke to make sure the TextBox has the latest text before filtering
        $form.BeginInvoke({
            $filter = $txtSearch.Text.Trim()
            if ($Global:UserTable) {
                $dv = New-Object System.Data.DataView($Global:UserTable)

                if ([string]::IsNullOrWhiteSpace($filter)) {
                    $dv.RowFilter = ""
                }
                else {
                    # escape single quotes to prevent filter syntax errors
                    $escaped = $filter.Replace("'", "''")
                    $dv.RowFilter = "Username LIKE '%$escaped%'"
                }

                $gridUsers.DataSource = $dv
            }
        })
    }
    catch {
        Write-Host "Filter Error: $($_.Exception.Message)"
    }
})
$txtSearch.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$txtSearch.BackColor = [System.Drawing.Color]::White
$txtSearch.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle



# --- Enable Selected ---
$btnEnableSelected.Add_Click({
    if ($gridUsers.SelectedRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please select a user first.","Warning","OK","Warning")
        return
    }
    $user = $gridUsers.SelectedRows[0].Cells["Username"].Value
    $msg = Enable-UserAccount -DC $Global:DCIP -TargetUser $user
    [System.Windows.Forms.MessageBox]::Show($msg,"Result","OK","Information")
    $txtOutput.AppendText("$msg`r`n")
})

# --- Disable Selected ---
$btnDisableSelected.Add_Click({
    if ($gridUsers.SelectedRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please select a user first.","Warning","OK","Warning")
        return
    }
    $user = $gridUsers.SelectedRows[0].Cells["Username"].Value
    $msg = Disable-UserAccount -DC $Global:DCIP -TargetUser $user
    [System.Windows.Forms.MessageBox]::Show($msg,"Result","OK","Information")
    $txtOutput.AppendText("$msg`r`n")
})
# --- Button: Check Users Created in the Last 10 Hours ---
$btnRecentUsers = New-Object System.Windows.Forms.Button
$btnRecentUsers.Text = "Recent Users Created"
$btnRecentUsers.Location = New-Object System.Drawing.Point(255, 35)
$btnRecentUsers.Size = New-Object System.Drawing.Size(90, 25)

$btnRecentUsers.Add_Click({
    try {
        if (-not $Global:DCIP -or -not $Global:AdminCredential) {
            [System.Windows.Forms.MessageBox]::Show(
                "Please connect and save admin credentials first under the Connection tab.",
                "Missing Info",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }

        $since = (Get-Date).AddHours(-6)
        $txtOutput.AppendText("Checking users created since $since ...`r`n")

        # Run AD query remotely on DC
        $recentUsers = Invoke-Command -ComputerName $Global:DCIP -Credential $Global:AdminCredential -ScriptBlock {
            param($since)
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            Get-ADUser -Filter { whenCreated -gt $using:since } -Properties whenCreated, Enabled |
                Select-Object Name, SamAccountName, Enabled, whenCreated |
                Sort-Object whenCreated -Descending
        } -ArgumentList $since -ErrorAction Stop

        if (-not $recentUsers -or $recentUsers.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No new users created in the last 10 hours.","No Results",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information)
            return
        }

        # Build datatable
        $table = New-Object System.Data.DataTable
        "Name","SamAccountName","Enabled","WhenCreated" | ForEach-Object { [void]$table.Columns.Add($_) }

        foreach ($u in $recentUsers) {
            $row = $table.NewRow()
            $row["Name"] = $u.Name
            $row["SamAccountName"] = $u.SamAccountName
            $row["Enabled"] = $u.Enabled
            $row["WhenCreated"] = $u.whenCreated
            $table.Rows.Add($row)
        }

        $gridUsers.DataSource = $table
        $gridUsers.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::DisplayedCells
        $txtOutput.AppendText("Displayed recently created users.`r`n")
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error fetching recent users: $($_.Exception.Message)","Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# --- Add controls ---
$tabUsers.Controls.AddRange(@(
    $lblSearch,$txtSearch,
    $btnRefreshUsers,$btnDeleteUser,$btnExportExcel,$btnEnableSelected,$btnDisableSelected,$btnRecentUsers,
    $gridUsers
))


# --- Add all controls to the tab ---
$tabPw.Controls.AddRange(@(
    $lblTargetUser,
    $txtTargetUser,
    $lblNewPw2,
    $txtNewPw2,
    $lblConfirmPw,
    $txtConfirmPw,
    $btnChangePw
))

#================ SERVICES & PORTS TAB ================#
$tabServices = New-Object System.Windows.Forms.TabPage
$tabServices.Text = "Services & Ports"

# --- Label ---
$lblSvcSearch = New-Object System.Windows.Forms.Label
$lblSvcSearch.Text = "Filter by Name:"
$lblSvcSearch.Location = New-Object System.Drawing.Point(20, 15)
$lblSvcSearch.AutoSize = $true

# --- Search Box ---
$txtSvcSearch = New-Object System.Windows.Forms.TextBox
$txtSvcSearch.Location = New-Object System.Drawing.Point(120, 12)
$txtSvcSearch.Size = New-Object System.Drawing.Size(180, 22)

# --- Buttons ---
$btnRefreshSvc = New-Object System.Windows.Forms.Button
$btnRefreshSvc.Text = "Refresh List"
$btnRefreshSvc.Location = New-Object System.Drawing.Point(320, 10)
$btnRefreshSvc.Size = New-Object System.Drawing.Size(90, 25)

$btnSaveSvcExcel = New-Object System.Windows.Forms.Button
$btnSaveSvcExcel.Text = "Save to Excel"
$btnSaveSvcExcel.Location = New-Object System.Drawing.Point(420, 10)
$btnSaveSvcExcel.Size = New-Object System.Drawing.Size(100, 25)

$btnStopSvc = New-Object System.Windows.Forms.Button
$btnStopSvc.Text = "Stop Selected"
$btnStopSvc.Location = New-Object System.Drawing.Point(540, 10)
$btnStopSvc.Size = New-Object System.Drawing.Size(100, 25)

# --- DataGridView ---
$gridServices = New-Object System.Windows.Forms.DataGridView
$gridServices.Location = New-Object System.Drawing.Point(20, 50)
$gridServices.Size = New-Object System.Drawing.Size(820, 360)  # Reduced width for cleaner fit
$gridServices.Anchor = 'Top, Left, Right, Bottom'              # Makes it resize with form
$gridServices.ReadOnly = $true
$gridServices.AllowUserToAddRows = $false
$gridServices.AllowUserToDeleteRows = $false
$gridServices.AutoGenerateColumns = $true
$gridServices.SelectionMode = "FullRowSelect"
$gridServices.MultiSelect = $false
$gridServices.BackgroundColor = [System.Drawing.Color]::WhiteSmoke
$gridServices.RowHeadersVisible = $true
$gridServices.ScrollBars = [System.Windows.Forms.ScrollBars]::Both

# ✅ Adjust columns to fit content but not exceed table width
$gridServices.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::AllCells
$gridServices.AutoSizeRowsMode = [System.Windows.Forms.DataGridViewAutoSizeRowsMode]::DisplayedCells
$gridServices.ColumnHeadersHeightSizeMode = [System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::AutoSize


# --- Load Remote Services and Ports ---
$btnRefreshSvc.Add_Click({
    try {
        if (-not $Global:DCIP -or -not $Global:AdminCredential) {
            [System.Windows.Forms.MessageBox]::Show("Please set and save the remote Domain Controller connection first.","Error","OK","Error")
            return
        }

        $txtOutput.AppendText("Refreshing remote services and ports on $($Global:DCIP)...`r`n")

        $remoteData = Invoke-Command -ComputerName $Global:DCIP -Credential $Global:AdminCredential -ScriptBlock {
            $svc = Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name, DisplayName, Status, StartType
            $ports = Get-NetTCPConnection -State Listen | Select-Object LocalPort, LocalAddress, OwningProcess, State
            return [PSCustomObject]@{ Services = $svc; Ports = $ports }
        } -ErrorAction Stop

        # --- Build the table ---
        $svcTable = New-Object System.Data.DataTable
        $svcTable.Columns.Add("Type")
        $svcTable.Columns.Add("Name")
        $svcTable.Columns.Add("DisplayName")
        $svcTable.Columns.Add("Status")
        $svcTable.Columns.Add("StartType")

        foreach ($s in $remoteData.Services) {
            $row = $svcTable.NewRow()
            $row["Type"]        = "Service"
            $row["Name"]        = $s.Name
            $row["DisplayName"] = $s.DisplayName
            $row["Status"]      = $s.Status
            $row["StartType"]   = $s.StartType
            $svcTable.Rows.Add($row)
        }

        foreach ($p in $remoteData.Ports) {
            $row = $svcTable.NewRow()
            $row["Type"]        = "Port"
            $row["Name"]        = $p.LocalPort
            $row["DisplayName"] = "N/A"
            $row["Status"]      = $p.State
            $row["StartType"]   = $p.LocalAddress
            $svcTable.Rows.Add($row)
        }

        $Global:SvcTable = $svcTable
        $gridServices.DataSource = $Global:SvcTable
        $gridServices.AutoResizeColumns()
        $txtOutput.AppendText("Remote services and ports loaded successfully.`r`n")
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error loading remote data: $($_.Exception.Message)","Error","OK","Error")
    }
})

# --- Real-time Filter ---
$txtSvcSearch.Add_TextChanged({
    $form.BeginInvoke({
        if ($Global:SvcTable) {
            $filter = $txtSvcSearch.Text.Trim()
            $dv = New-Object System.Data.DataView($Global:SvcTable)
            if ([string]::IsNullOrWhiteSpace($filter)) {
                $dv.RowFilter = ""
            } else {
                $escaped = $filter.Replace("'", "''")
                $dv.RowFilter = "Name LIKE '%$escaped%'"
            }
            $gridServices.DataSource = $dv
        }
    })
})

# --- Save to Excel (Choose Path) ---
$btnSaveSvcExcel.Add_Click({
    try {
        if (-not $Global:SvcTable -or $Global:SvcTable.Rows.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No data to export.","Error","OK","Error")
            return
        }

        # Create Save File Dialog
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = "Excel Files (*.xlsx)|*.xlsx"
        $saveDialog.Title = "Save Services & Ports Report"
        $saveDialog.FileName = "Remote_Services_and_Ports.xlsx"

        if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $path = $saveDialog.FileName
            $excel = New-Object -ComObject Excel.Application
            $excel.Visible = $false
            $wb = $excel.Workbooks.Add()
            $ws = $wb.Worksheets.Item(1)

            # headers
            for ($i=0; $i -lt $Global:SvcTable.Columns.Count; $i++) {
                $ws.Cells.Item(1, $i + 1) = $Global:SvcTable.Columns[$i].ColumnName
            }

            # data
            for ($r=0; $r -lt $Global:SvcTable.Rows.Count; $r++) {
                for ($c=0; $c -lt $Global:SvcTable.Columns.Count; $c++) {
                    $ws.Cells.Item($r + 2, $c + 1) = $Global:SvcTable.Rows[$r][$c]
                }
            }

            $wb.SaveAs($path)
            $excel.Quit()
            [System.Windows.Forms.MessageBox]::Show("Exported successfully to:`r`n$path","Export Successful","OK","Information")
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error exporting data: $($_.Exception.Message)","Error","OK","Error")
    }
})



# --- Remote Stop Service ---
$btnStopSvc.Add_Click({
    try {
        if ($gridServices.SelectedRows.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("Please select a service to stop.","Error","OK","Error")
            return
        }

        $selected = $gridServices.SelectedRows[0].Cells["Name"].Value

        # ✅ Confirmation prompt BEFORE running remote command
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Are you sure you want to stop '$selected' on $($Global:DCIP)?",
            "Confirm",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )

        if ($result -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        # ✅ Remote stop after confirmation
        Invoke-Command -ComputerName $Global:DCIP -Credential $Global:AdminCredential -ScriptBlock {
            param($svc)
            Stop-Service -Name $svc -Force -ErrorAction Stop
        } -ArgumentList $selected

        [System.Windows.Forms.MessageBox]::Show("Service '$selected' stopped successfully on $($Global:DCIP).",
            "Success","OK",[System.Windows.Forms.MessageBoxIcon]::Information)
        $btnRefreshSvc.PerformClick()
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error stopping service: $($_.Exception.Message)","Error","OK","Error")
    }
})

# --- Add controls ---
$tabServices.Controls.AddRange(@(
    $lblSvcSearch, $txtSvcSearch,
    $btnRefreshSvc, $btnSaveSvcExcel,
    $btnStopSvc,
    $gridServices
))

# ================= VULNERABILITY CHECKS TAB (PowerShell-only, read-only) ================= #
# Drop this block into your script before you add tabs into $tabs.Controls.AddRange(...)

$tabVuln = New-Object System.Windows.Forms.TabPage
$tabVuln.Text = "Vulnerability Checks (PS)"

# ---- Label and Target Textbox ----
$lblTarget = New-Object System.Windows.Forms.Label
$lblTarget.Text = "Target (saved):"
$lblTarget.Location = New-Object System.Drawing.Point(20, 15)
$lblTarget.AutoSize = $true

$txtTarget = New-Object System.Windows.Forms.TextBox
$txtTarget.Location = New-Object System.Drawing.Point(120, 12)
$txtTarget.Size = New-Object System.Drawing.Size(200, 22)
$txtTarget.ReadOnly = $true

# ---- Checkboxes (Two Rows) ----
$chkSMB = New-Object System.Windows.Forms.CheckBox
$chkSMB.Text = "SMB config (SMBv1 / signing)"
$chkSMB.Location = New-Object System.Drawing.Point(20, 55)
$chkSMB.AutoSize = $true
$chkSMB.Checked = $true

$chkNetlogon = New-Object System.Windows.Forms.CheckBox
$chkNetlogon.Text = "Netlogon indicators (ZeroLogon)"
$chkNetlogon.Location = New-Object System.Drawing.Point(250, 55)
$chkNetlogon.AutoSize = $true
$chkNetlogon.Checked = $true

$chkACL = New-Object System.Windows.Forms.CheckBox
$chkACL.Text = "AD ACL replication rights (DCSync hints)"
$chkACL.Location = New-Object System.Drawing.Point(480, 55)
$chkACL.AutoSize = $true
$chkACL.Checked = $true

# Second row
$chkDNS = New-Object System.Windows.Forms.CheckBox
$chkDNS.Text = "DNS zone transfer settings"
$chkDNS.Location = New-Object System.Drawing.Point(20, 80)
$chkDNS.AutoSize = $true
$chkDNS.Checked = $true

$chkHost = New-Object System.Windows.Forms.CheckBox
$chkHost.Text = "Host OS & Hotfixes"
$chkHost.Location = New-Object System.Drawing.Point(250, 80)
$chkHost.AutoSize = $true
$chkHost.Checked = $true

# ---- Buttons ----
$btnRun = New-Object System.Windows.Forms.Button
$btnRun.Text = "Run PS Checks"
$btnRun.Location = New-Object System.Drawing.Point(480, 12)
$btnRun.Size = New-Object System.Drawing.Size(120, 28)

$btnSave = New-Object System.Windows.Forms.Button
$btnSave.Text = "Save Report..."
$btnSave.Location = New-Object System.Drawing.Point(610, 12)
$btnSave.Size = New-Object System.Drawing.Size(120, 28)

# ---- Output textbox ----
$txtVulnOut = New-Object System.Windows.Forms.TextBox
$txtVulnOut.Multiline = $true
$txtVulnOut.Location = New-Object System.Drawing.Point(20, 120)
$txtVulnOut.Size = New-Object System.Drawing.Size(760, 360)
$txtVulnOut.ScrollBars = "Both"
$txtVulnOut.ReadOnly = $true
$txtVulnOut.Font = New-Object System.Drawing.Font("Consolas",9)


# Show saved target when entering tab
$tabVuln.Add_Enter({
    $txtTarget.Text = $Global:DCIP
})

# ---------------- Helper: safe remote execution wrapper ----------------
function Invoke-RemoteSafe {
    param(
        [Parameter(Mandatory=$true)][string]$ComputerName,
        [Parameter(Mandatory=$true)][pscredential]$Credential,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock
    )
    try {
        return Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $ScriptBlock -ErrorAction Stop
    } catch {
        return "ERROR REMOTE: $($_.Exception.Message)"
    }
}

# ---------------- Run button logic ----------------
$btnRun.Add_Click({
    try {
        $txtVulnOut.Clear()
        if (-not $Global:DCIP) {
            [System.Windows.Forms.MessageBox]::Show("Please save the Domain Controller IP on the Connection tab.","Error",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error)
            return
        }
        $target = $Global:DCIP
        $txtVulnOut.AppendText("PS Vulnerability Checks - Target: $target`r`n")
        $txtVulnOut.AppendText("Started: $(Get-Date -Format 'u')`r`n`r`n")

        # 1) Host OS + hotfix summary
        if ($chkHost.Checked) {
            $txtVulnOut.AppendText("== Host OS + Installed Hotfixes (summary) ==`r`n")
            $hostInfo = Invoke-RemoteSafe -ComputerName $target -Credential $Global:AdminCredential -ScriptBlock {
                try {
                    $os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
                    $hotfixes = Get-HotFix | Select-Object -First 25 HotFixID, InstalledOn
                    return @{ OS = $os; Hotfixes = $hotfixes }
                } catch {
                    return "ERROR: $($_.Exception.Message)"
                }
            }

            if ($hostInfo -is [string]) {
                $txtVulnOut.AppendText("$hostInfo`r`n`r`n")
            } else {
                $txtVulnOut.AppendText("OS: " + ($hostInfo.OS.Caption -join "") + " (Version " + $hostInfo.OS.Version + " Build " + $hostInfo.OS.BuildNumber + ")`r`n")
                $txtVulnOut.AppendText("Recent Hotfixes (first 25):`r`n")
                foreach ($h in $hostInfo.Hotfixes) { $txtVulnOut.AppendText("  " + $h.HotFixID + "  " + $h.InstalledOn + "`r`n") }
                $txtVulnOut.AppendText("`r`n")
            }
        }

        # 2) SMB config checks
        # 2) SMB config checks (fixed ternary operators)
        if ($chkSMB.Checked) {
            $txtVulnOut.AppendText("== SMB configuration checks ==`r`n")
            $smb = Invoke-RemoteSafe -ComputerName $target -Credential $Global:AdminCredential -ScriptBlock {
                try {
                    $cfg = $null
                    try { $cfg = Get-SmbServerConfiguration -ErrorAction Stop } catch {}

                    if ($cfg) {
                        return @{
                            SMBv1 = $cfg.EnableSMB1Protocol
                            RequireSecuritySignature = $cfg.RequireSecuritySignature
                            EnableSecuritySignature = $cfg.EnableSecuritySignature
                        }
                    } else {
                        # fallback to registry if Get-SmbServerConfiguration fails
                        $reg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ErrorAction SilentlyContinue
                        $smb1 = $null
                        if ($reg -ne $null) {
                            if ($reg.PSObject.Properties.Name -contains 'SMB1') { $smb1 = $reg.SMB1 }
                            elseif ($reg.PSObject.Properties.Name -contains 'SMB1Enabled') { $smb1 = $reg.SMB1Enabled }
                        }

                        $require = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
                                                    -Name "RequireSecuritySignature","EnableSecuritySignature" `
                                                    -ErrorAction SilentlyContinue

                        $valSMB1 = if ($null -ne $smb1) { $smb1 } else { "unknown" }
                        $valReqSig = if ($null -ne $require.RequireSecuritySignature) { $require.RequireSecuritySignature } else { "N/A" }
                        $valEnSig = if ($null -ne $require.EnableSecuritySignature) { $require.EnableSecuritySignature } else { "N/A" }

                        return @{
                            SMBv1 = $valSMB1
                            RequireSecuritySignature = $valReqSig
                            EnableSecuritySignature = $valEnSig
                        }
                    }
                } catch {
                    return "ERROR: $($_.Exception.Message)"
                }
            }

            if ($smb -is [string]) {
                $txtVulnOut.AppendText("$smb`r`n`r`n")
            } else {
                $txtVulnOut.AppendText("SMBv1 enabled: $($smb.SMBv1)`r`n")
                $txtVulnOut.AppendText("RequireSecuritySignature: $($smb.RequireSecuritySignature)`r`n")
                $txtVulnOut.AppendText("EnableSecuritySignature : $($smb.EnableSecuritySignature)`r`n")
                $txtVulnOut.AppendText("Note: SMBv1 + missing MS17-010 patches is an indicator; check hotfixes.`r`n`r`n")
            }
        }


        # 3) Netlogon indicators (ZeroLogon)
        if ($chkNetlogon.Checked) {
        $txtVulnOut.AppendText("== Netlogon (ZeroLogon) indicators ==`r`n")

        $nl = Invoke-RemoteSafe -ComputerName $target -Credential $Global:AdminCredential -ScriptBlock {
            try {
                # keys we want to inspect: modern + legacy
                $keys = @(
                    "FullSecureChannelProtection",
                    "RequireSignOrSeal",
                    "RequireSigning",            # legacy name (may not exist)
                    "RequireSeal",
                    "RequireStrongKey",
                    "DisablePasswordChange"
                )

                $regOut = @{}
                foreach ($k in $keys) {
                    $val = $null
                    try {
                        $prop = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name $k -ErrorAction SilentlyContinue
                        if ($prop -ne $null) { $val = $prop.$k }
                    } catch {
                        $val = $null
                    }

                    # Normalize numeric -> friendly text
                    switch ($val) {
                        { $_ -eq $null } { $regOut[$k] = "not set"; break }
                        0 { $regOut[$k] = "0 (Disabled)"; break }
                        1 { $regOut[$k] = "1 (Enabled)"; break }
                        default { $regOut[$k] = "$val (Unknown)"; break }
                    }
                }

                $svc = Get-Service -Name Netlogon -ErrorAction SilentlyContinue | Select-Object Name, Status

                return @{
                    NetlogonRegistry = $regOut
                    NetlogonService  = $svc
                }
            } catch {
                return "ERROR: $($_.Exception.Message)"
            }
        }

        # handle results the same way you did, but print friendlier strings
        if ($nl -is [string]) {
            $txtVulnOut.AppendText("$nl`r`n`r`n")
        } else {
            # Print a useful preferred summary order
            $preferredOrder = @(
                "FullSecureChannelProtection",
                "RequireSignOrSeal",
                "RequireSigning",
                "RequireSeal",
                "RequireStrongKey",
                "DisablePasswordChange"
            )
            foreach ($k in $preferredOrder) {
                if ($nl.NetlogonRegistry.ContainsKey($k)) {
                    $txtVulnOut.AppendText("  $k = $($nl.NetlogonRegistry[$k])`r`n")
                }
            }

            if ($nl.NetlogonService) {
                $txtVulnOut.AppendText("Netlogon service status: " + $nl.NetlogonService.Status + "`r`n")
            }

            $txtVulnOut.AppendText("Guidance: ensure ZeroLogon patches applied and Netlogon secure channel enforcement set as required by MS guidance.`r`n`r`n")
        }
}


        # 4) AD ACL replication rights (DCSync hint)
        if ($chkACL.Checked) {
            $txtVulnOut.AppendText("== AD ACL check: Principals with ReplicateDirectoryChanges/All rights ==`r`n")
            $aclResult = Invoke-RemoteSafe -ComputerName $target -Credential $Global:AdminCredential -ScriptBlock {
                try {
                    Import-Module ActiveDirectory -ErrorAction Stop
                    $domainDN = (Get-ADDomain).DistinguishedName
                    $adPath = "AD:$domainDN"
                    $acl = Get-Acl -Path $adPath
                    $out = @()
                    foreach ($ace in $acl.Access) {
                        $rights = $ace.ActiveDirectoryRights
                        $replicateBits = [System.DirectoryServices.ActiveDirectoryRights]::ReplicateDirectoryChanges -bor [System.DirectoryServices.ActiveDirectoryRights]::ReplicateDirectoryChangesAll
                        if ( ($rights -band $replicateBits) -ne 0 ) {
                            $out += @{ Identity = $ace.IdentityReference.ToString(); Rights = $ace.ActiveDirectoryRights.ToString(); Type = $ace.AccessControlType.ToString() }
                        }
                    }
                    if ($out.Count -eq 0) { return "No principals with replicate rights found on domain root (quick check)." }
                    return $out
                } catch { return "ERROR (AD ACL check): $($_.Exception.Message)" }
            }

            if ($aclResult -is [string]) {
                $txtVulnOut.AppendText("$aclResult`r`n`r`n")
            } else {
                foreach ($entry in $aclResult) {
                    $txtVulnOut.AppendText("  " + $entry.Identity + "  Rights: " + $entry.Rights + "  Type: " + $entry.Type + "`r`n")
                }
                $txtVulnOut.AppendText("`r`n")
            }
        }

        # 5) DNS zone transfer openness (if DNS Server module present)
        if ($chkDNS.Checked) {
            $txtVulnOut.AppendText("== DNS zone transfer settings (if DNS role present) ==`r`n")
            $dnsRes = Invoke-RemoteSafe -ComputerName $target -Credential $Global:AdminCredential -ScriptBlock {
                try {
                    Import-Module DNSServer -ErrorAction Stop
                    $zones = Get-DnsServerZone -ErrorAction Stop
                    $out = @()
                    foreach ($z in $zones) {
                        $out += @{ ZoneName = $z.ZoneName; ZoneType = $z.ZoneType; AllowTransfer = $z.AllowTransfer }
                    }
                    return $out
                } catch { return "DNS module not present / cannot query DNS role: $($_.Exception.Message)" }
            }

            if ($dnsRes -is [string]) {
                $txtVulnOut.AppendText("$dnsRes`r`n`r`n")
            } else {
                foreach ($z in $dnsRes) {
                    $txtVulnOut.AppendText("  " + $z.ZoneName + "  Type: " + $z.ZoneType + "  AllowTransfer: " + $z.AllowTransfer + "`r`n")
                }
                $txtVulnOut.AppendText("`r`n")
            }
        }

        # Final summary/notes
        $txtVulnOut.AppendText("== Quick summary hints ==`r`n")
        $txtVulnOut.AppendText(" - If SMBv1 enabled -> consider disabling SMBv1 and ensure MS17-010 patches are applied.`r`n")
        $txtVulnOut.AppendText(" - If Netlogon registry keys don't enforce signing/seal -> verify ZeroLogon patches and enforcement settings.`r`n")
        $txtVulnOut.AppendText(" - Principals with ReplicateDirectoryChanges* rights -> review and remove if not required (DCSync risk).`r`n")
        $txtVulnOut.AppendText(" - DNS zones allowing transfers widely -> restrict to specific servers.`r`n")
        $txtVulnOut.AppendText("Checks finished: $(Get-Date -Format 'u')`r`n")
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error running PS checks: $($_.Exception.Message)","Error",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# ---------------- Save button ----------------
$btnSave.Add_Click({
    try {
        $save = New-Object System.Windows.Forms.SaveFileDialog
        $save.Filter = "Text Files (*.txt)|*.txt|All files (*.*)|*.*"
        $save.FileName = "ps_vuln_report_$($Global:DCIP)_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        if ($save.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            [System.IO.File]::WriteAllText($save.FileName, $txtVulnOut.Text)
            [System.Windows.Forms.MessageBox]::Show("Saved to $($save.FileName)","Saved",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Save error: $($_.Exception.Message)","Error",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# Add controls to the tab
$tabVuln.Controls.AddRange(@(
    $lblTarget, $txtTarget,
    $chkHost, $chkSMB, $chkNetlogon, $chkACL, $chkDNS,
    $btnRun, $btnSave,
    $txtVulnOut
))
# ============================================================================================
# ================= AUTHENTICATION HARDENING TAB ================= #
$tabAuthHardening = New-Object System.Windows.Forms.TabPage
$tabAuthHardening.Text = "Auth Hardening Audit"

# UI controls
$lblTargetAuth = New-Object System.Windows.Forms.Label
$lblTargetAuth.Text = "Target (saved):"
$lblTargetAuth.Location = New-Object System.Drawing.Point(20,15)
$lblTargetAuth.AutoSize = $true

$txtTargetAuth = New-Object System.Windows.Forms.TextBox
$txtTargetAuth.Location = New-Object System.Drawing.Point(140,12)
$txtTargetAuth.Size = New-Object System.Drawing.Size(220,22)
$txtTargetAuth.ReadOnly = $true

$btnRunAuth = New-Object System.Windows.Forms.Button
$btnRunAuth.Text = "Run Audit"
$btnRunAuth.Location = New-Object System.Drawing.Point(380,10)
$btnRunAuth.Size = New-Object System.Drawing.Size(100,26)

$btnSaveAuth = New-Object System.Windows.Forms.Button
$btnSaveAuth.Text = "Save Report..."
$btnSaveAuth.Location = New-Object System.Drawing.Point(490,10)
$btnSaveAuth.Size = New-Object System.Drawing.Size(110,26)

# Output grid (datatable style)
$gridAuth = New-Object System.Windows.Forms.DataGridView
$gridAuth.Location = New-Object System.Drawing.Point(20,50)
$gridAuth.Size = New-Object System.Drawing.Size(760,420)
$gridAuth.ReadOnly = $true
$gridAuth.AllowUserToAddRows = $false
$gridAuth.AllowUserToDeleteRows = $false
$gridAuth.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
$gridAuth.SelectionMode = "FullRowSelect"
$gridAuth.ScrollBars = [System.Windows.Forms.ScrollBars]::Both
$gridAuth.MultiSelect = $false
$gridAuth.RowHeadersVisible = $true
$gridAuth.BackgroundColor = [System.Drawing.Color]::WhiteSmoke

# Show saved target when entering tab
$tabAuthHardening.Add_Enter({
    $txtTargetAuth.Text = $Global:DCIP
})

# Helper: safe remote execution wrapper (local to this tab)
function Invoke-RemoteSafe {
    param(
        [Parameter(Mandatory=$true)][string]$ComputerName,
        [Parameter(Mandatory=$true)][pscredential]$Credential,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock
    )
    try {
        return Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $ScriptBlock -ErrorAction Stop
    } catch {
        return "ERROR REMOTE: $($_.Exception.Message)"
    }
}

# Build a DataTable for results
function New-AuthResultTable {
    $dt = New-Object System.Data.DataTable
    $dt.Columns.Add("Check") | Out-Null
    $dt.Columns.Add("Value") | Out-Null
    $dt.Columns.Add("Notes") | Out-Null
    return $dt
}

# Run audit
$btnRunAuth.Add_Click({
    try {
        if (-not $Global:DCIP -or -not $Global:AdminCredential) {
            [System.Windows.Forms.MessageBox]::Show(
                "Please connect and save credentials first under the Connection tab.",
                "Missing Info",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }

        $target = $Global:DCIP
        $cred = $Global:AdminCredential
        $gridAuth.DataSource = $null

        # --- Build table with color-coded status ---
        $dt = New-Object System.Data.DataTable
        $dt.Columns.Add("Check") | Out-Null
        $dt.Columns.Add("Value") | Out-Null
        $dt.Columns.Add("Status") | Out-Null
        $dt.Columns.Add("Notes") | Out-Null

        function SafeInvoke {
            param([scriptblock]$Script)
            try {
                if (-not $Script) { return "N/A" }
                $r = Invoke-Command -ComputerName $target -Credential $cred -ScriptBlock $Script -ErrorAction Stop
                if ($r -eq $null) { return "N/A" } else { return $r }
            } catch { return "ERROR: $($_.Exception.Message)" }
        }

        # === NTLM Compatibility ===
        $lm = SafeInvoke {
            (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
        }
        $desc = switch ($lm) {
            0 {"❌ LM & NTLM allowed (very insecure)"} 
            1 {"⚠️ NTLMv2 if negotiated (weak)"} 
            2 {"⚠️ NTLMv1 only (obsolete)"}
            3 {"✅ NTLMv2 only (ok)"}
            4 {"✅ Refuses LM (good)"}
            5 {"🟢 Refuses LM + NTLMv1 (best)"}
            default {"Unknown or not set"}
        }
        $status = if ($lm -eq 5) {"Secure"} elseif ($lm -ge 3) {"Moderate"} else {"Vulnerable"}
        $dt.Rows.Add("NTLM Compatibility Level",$lm,$status,$desc)

        # === SMB Configuration ===
        $smb = SafeInvoke { Get-SmbServerConfiguration }
        if ($smb -isnot [string]) {
            $dt.Rows.Add("SMBv1 Installed",$smb.EnableSMB1Protocol,($(if ($smb.EnableSMB1Protocol){"Vulnerable"}else{"Secure"})),"SMBv1 allows EternalBlue-style exploits")
            $dt.Rows.Add("Require Security Signature",$smb.RequireSecuritySignature,($(if ($smb.RequireSecuritySignature){"Secure"}else{"Vulnerable"})),"Unsigned SMB allows tampering")
            $dt.Rows.Add("Encrypt Data",$smb.EncryptData,($(if ($smb.EncryptData){"Secure"}else{"Optional"})),"Recommended to protect SMB data-in-transit")
        } else {
            $dt.Rows.Add("SMB Config","Error","❌","$smb")
        }

        # === Anonymous LSA & SAM Enumeration ===
        $anon = SafeInvoke {
            (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ErrorAction SilentlyContinue).RestrictAnonymous
        }
        $status = switch ($anon) {
            0 {"Vulnerable"}
            1 {"Moderate"}
            2 {"Secure"}
            default {"Unknown"}
        }
        $dt.Rows.Add("Anonymous Enumeration",$anon,$status,"0=Permits null session enumeration; 2=Disabled")

        # === LDAP Signing ===
        $ldap = SafeInvoke {
            (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue).LDAPServerIntegrity
        }
        $status = switch ($ldap) {
            2 {"Secure"}
            1 {"Negotiated"}
            default {"Vulnerable"}
        }
        $dt.Rows.Add("LDAP Signing",$ldap,$status,"1=Negotiate, 2=Require")

        # === LDAP Channel Binding Enforcement ===
        $ldapbind = SafeInvoke {
            (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPEnforceChannelBinding" -ErrorAction SilentlyContinue).LDAPEnforceChannelBinding
        }
        $status = if ($ldapbind -eq 2) {"Secure"} elseif ($ldapbind -eq 1) {"Moderate"} else {"Vulnerable"}
        $dt.Rows.Add("LDAP Channel Binding",$ldapbind,$status,"2=Require; mitigates CVE-2020 LDAP relay attacks.")

        # === RDP Network Level Auth ===
        $nla = SafeInvoke {
            (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
        }
        $status = if ($nla -eq 1) {"Secure"} else {"Vulnerable"}
        $dt.Rows.Add("RDP Network Level Auth",$nla,$status,"0=Disabled, 1=Enabled (required for secure RDP)")

        # === PowerShell Constrained Language Mode ===
        $clm = SafeInvoke { $ExecutionContext.SessionState.LanguageMode.ToString() }
        $status = if ($clm -eq "ConstrainedLanguage") {"Secure"} else {"FullLanguage (Monitor usage)"}
        $dt.Rows.Add("PowerShell Language Mode",$clm,$status,"ConstrainedLanguage limits attacker scripts")

        # === Kerberos Lifetime Policy ===
        $kerb = SafeInvoke {
            $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
            if (Test-Path $path) {
                Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                Select-Object MaxTicketAge, MaxRenewAge
            } else {
                $null
            }
        }

        if ($kerb -and $kerb.MaxTicketAge) {
            $dt.Rows.Add("Kerberos MaxTicketAge", $kerb.MaxTicketAge, "Info", "Ticket lifetime in hours (default 10)")
            $dt.Rows.Add("Kerberos MaxRenewAge", $kerb.MaxRenewAge, "Info", "Renewable lifetime in hours (default 7 days)")
        } else {
            $dt.Rows.Add("Kerberos Policy", "Default in use", "Secure", "Using default secure values (MaxTicketAge=10h, MaxRenewAge=7d)")
        }



        # === Null Session Shares ===
        $nullShares = SafeInvoke {
            $shares = net share | Out-String
            if ($shares -match "Everyone|All Users|Tout le monde|Todos") { $true } else { $false }
        }
        $status = if ($nullShares) {"Vulnerable"} else {"Secure"}
        $shareValue = if ($nullShares) {"Found"} else {"None"}
        $dt.Rows.Add("Null Session Shares",$shareValue,$status,"Shares accessible by Everyone allow anonymous access")


    # === LLMNR (Link-Local Multicast Name Resolution) ===
     $llmnr = SafeInvoke {
                    try {
                        $val = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
                        if ($null -eq $val) {
                            return "Missing"
                        } else {
                            return $val
                        }
                    } catch {
                        return "Error"
                    }
                }

                switch ($llmnr) {
                    "Missing" {
                        $status = "Vulnerable"
                        $desc   = "LLMNR policy not set (default = enabled)"
                    }
                    1 {
                        $status = "Vulnerable"
                        $desc   = "LLMNR enabled — allows Responder/poisoning attacks"
                    }
                    0 {
                        $status = "Secure"
                        $desc   = "LLMNR disabled via policy"
                    }
                    default {
                        $status = "Unknown"
                        $desc   = "Unable to determine LLMNR state"
                    }
                }

                $dt.Rows.Add("LLMNR Status", $llmnr, $status, $desc)

        # === LSASS & Credential Protection ===
        $lsass = SafeInvoke {
            (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
        }
        $status = if ($lsass -eq 1) {"Secure"} else {"Vulnerable"}
        $dt.Rows.Add("LSA Protection (RunAsPPL)",$lsass,$status,"Prevents LSASS dumping via Mimikatz; requires reboot to enable.")

        $wdigest = SafeInvoke {
            (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential
        }
        $status = if ($wdigest -eq 0 -or $null -eq $wdigest) {"Secure"} else {"Vulnerable"}
        $dt.Rows.Add("WDigest UseLogonCredential",$wdigest,$status,"0=Disabled (secure); prevents plaintext creds in LSASS.")

        # === Netlogon / ZeroLogon Protection ===
        $netlogon = SafeInvoke {
            Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ErrorAction SilentlyContinue |
            Select-Object FullSecureChannelProtection,RequireSeal,RequireStrongKey
        }
        if ($netlogon -isnot [string]) {
            $dt.Rows.Add("Netlogon Secure Channel",$netlogon.FullSecureChannelProtection,
                ($(if ($netlogon.FullSecureChannelProtection -eq 1){"Secure"}else{"Vulnerable"})),
                "ZeroLogon protection; requires 1 for enforcement.")
            $dt.Rows.Add("Netlogon StrongKey",$netlogon.RequireStrongKey,
                ($(if ($netlogon.RequireStrongKey -eq 1){"Secure"}else{"Vulnerable"})),
                "Ensure secure key exchange (1=Enabled).")
        }

        # === SMB Client Signing Enforcement ===
        $smbclient = SafeInvoke {
            (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
        }
        $status = if ($smbclient -eq 1) {"Secure"} else {"Vulnerable"}
        $dt.Rows.Add("SMB Client Signing",$smbclient,$status,"Require signing for outgoing SMB connections.")

        # === NTLM Restrictions ===
        $ntlm = SafeInvoke {
            (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue).RestrictSendingNTLMTraffic
        }
        $status = switch ($ntlm) {
            0 {"Vulnerable"}
            1 {"Moderate"}
            2 {"Secure"}
            default {"Unknown"}
        }
        $dt.Rows.Add("Restrict NTLM Traffic",$ntlm,$status,"0=Allow all, 1=Audit, 2=Deny (preferred).")

        

       # === DNS Zone Transfer Security (Improved) ===
        $zones = SafeInvoke { Get-DnsServerZone | Select ZoneName, SecureSecondaries, ZoneType }
        if ($zones -and $zones -isnot [string]) {
            foreach ($z in $zones) {
                # Skip known system or reserved zones that are read-only
                # Handle system, reserved, or non-primary zones consistently
                if ($z.ZoneName -match '^(0\.|127\.|255\.|TrustAnchors|_msdcs)') {
                    # System or reserved zones (read-only)
                    $status = "Secure"
                    $desc = "System or reserved zone (read-only, automatically secured)"
                    $dt.Rows.Add("DNS Zone Transfer: $($z.ZoneName)", "SystemZone", $status, $desc)
                    continue
                }

                # Skip non-primary zones (Secondary, Stub, Forward)
                if ($z.ZoneType -ne "Primary") {
                    $status = "N/A"
                    $desc = "Non-primary zone ($($z.ZoneType)) – not configurable on this server"
                    $dt.Rows.Add("DNS Zone Transfer: $($z.ZoneName)", $z.ZoneType, $status, $desc)
                    continue
                }


                $desc = "SecureSecondaries=$($z.SecureSecondaries)"
                switch ($z.SecureSecondaries) {
                    "NoTransfer" { 
                        $status = "Secure" 
                        $desc = "Zone transfer disabled (NoTransfer)" 
                    }
                    "TransferToSecureServers" { 
                        $status = "Secure" 
                        $desc = "Transfers allowed only to authorized DNS servers" 
                    }
                    "SecureOnly" { 
                        $status = "Moderate" 
                        $desc = "Legacy setting: only secure connections allowed" 
                    }
                    default { 
                        $status = "Vulnerable" 
                        $desc = "Transfers may be allowed: SecureSecondaries=$($z.SecureSecondaries)" 
                    }
                }

                $dt.Rows.Add("DNS Zone Transfer: $($z.ZoneName)", $z.SecureSecondaries, $status, $desc)
            }
        } else {
            $dt.Rows.Add("DNS Zone Transfers","Unknown","Unknown","Unable to query DNS zones or insufficient privileges.")
        }

        # === Audit Policy Configuration ===
        $audit = SafeInvoke { auditpol /get /category:* | Out-String }
        if ($audit -match "No Auditing") {
            $dt.Rows.Add("Advanced Audit Policy","Partial","Moderate","Some categories not auditing events.")
        } elseif ($audit -is [string]) {
            $dt.Rows.Add("Advanced Audit Policy","Enabled","Secure","Account Logon, Object Access, and DS Access events are logged.")
        } else {
            $dt.Rows.Add("Advanced Audit Policy","Unknown","Unknown","Could not determine audit configuration.")
        }

        # --- Credential Guard detection ---
        $deviceGuard = Get-CimInstance -Namespace "root\Microsoft\Windows\DeviceGuard" -ClassName Win32_DeviceGuard
        $servicesConfigured = $deviceGuard.SecurityServicesConfigured
        $servicesRunning    = $deviceGuard.SecurityServicesRunning

        if ($servicesRunning -match "1|2") {
            $dt.Rows.Add("Credential Guard","Running","Secure","Credential Guard is active and running.")
        }
        elseif ($servicesConfigured -eq 0 -and (Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue) -eq 1) {
            $dt.Rows.Add("Credential Guard","N/A","N/A","Not supported in VM; LSASS RunAsPPL is active (secure equivalent).")
        }
        else {
            $dt.Rows.Add("Credential Guard","0","Vulnerable","Credential Guard not running or unsupported.")
        }

        # === Summary Row ===
        $dt.Rows.Add("Summary","Review colored indicators","Secure  Moderate  Vulnerable","Apply Microsoft and DoD STIG baselines")

        # --- Show in grid ---
        $gridAuth.DataSource = $dt
        $gridAuth.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI",10,[System.Drawing.FontStyle]::Bold)
        $gridAuth.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::Gainsboro
        $gridAuth.EnableHeadersVisualStyles = $false

        $gridAuth.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::DisplayedCells
        $gridAuth.ScrollBars = [System.Windows.Forms.ScrollBars]::Both
        # === UI Formatting Enhancements ===
        $gridAuth.Columns["Status"].DefaultCellStyle.Alignment = "MiddleCenter"
        $gridAuth.Columns["Status"].DefaultCellStyle.BackColor = [System.Drawing.Color]::White
        $gridAuth.Columns["Status"].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black

        # === Color-code by status ===
        foreach ($row in $gridAuth.Rows) {
            switch ($row.Cells["Status"].Value) {
                "Secure"     { $row.Cells["Status"].Style.BackColor = [System.Drawing.Color]::LightGreen }
                "Moderate"   { $row.Cells["Status"].Style.BackColor = [System.Drawing.Color]::Khaki }
                "Vulnerable" { $row.Cells["Status"].Style.BackColor = [System.Drawing.Color]::Salmon }
                default      { $row.Cells["Status"].Style.BackColor = [System.Drawing.Color]::White }
            }
        }


    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Audit failed: $($_.Exception.Message)","Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})


# Save report as CSV or text
$btnSaveAuth.Add_Click({
    try {
        if ($null -eq $gridAuth.DataSource) {
            [System.Windows.Forms.MessageBox]::Show("No audit results to save. Run the audit first.","No Data",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        $save = New-Object System.Windows.Forms.SaveFileDialog
        $save.Filter = "CSV Files (*.csv)|*.csv|Text Files (*.txt)|*.txt"
        $save.FileName = "Auth_Hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        if ($save.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $path = $save.FileName
            $dt = $gridAuth.DataSource
            if ($path.ToLower().EndsWith(".csv")) {
                # Convert DataTable to CSV
                $rows = @()
                foreach ($r in $dt.Rows) {
                    $obj = @{}
                    for ($i=0; $i -lt $dt.Columns.Count; $i++) {
                        $col = $dt.Columns[$i].ColumnName
                        $obj[$col] = $r[$i]
                    }
                    $rows += New-Object PSObject -Property $obj
                }
                $rows | Export-Csv -Path $path -NoTypeInformation -Force
            } else {
                # text format
                $sb = New-Object System.Text.StringBuilder
                foreach ($r in $dt.Rows) {
                    $sb.AppendLine("$($r["Check"])`t$($r["Value"])`t$($r["Notes"]))") | Out-Null
                }
                [System.IO.File]::WriteAllText($path, $sb.ToString())
            }
            [System.Windows.Forms.MessageBox]::Show("Saved to $path","Saved",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Save error: $($_.Exception.Message)","Error",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# Add controls to tab
$tabAuthHardening.Controls.AddRange(@($lblTargetAuth,$txtTargetAuth,$btnRunAuth,$btnSaveAuth,$gridAuth))
# =================================================================== #

#================ ADD TABS TO FORM ================#
$tabs.Controls.AddRange(@($tabConn, $tabCreate, $tabPw, $tabUsers, $tabServices, $tabVuln, $tabAuthHardening))
$form.Controls.AddRange(@($tabs, $txtOutput))

#================ RUN APPLICATION ================#
$form.Show()
[System.Windows.Forms.Application]::DoEvents()
[System.Windows.Forms.Application]::Run($form)

