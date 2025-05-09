
### TrayToy
$appVersion = "1.0.0.0"
$appName = "TrayToy"

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

# Hide powershell console (if not running in Powershell ISE)
if ((Get-Process -PID $pid).ProcessName -ne "powershell_ise") { $null = $(Add-Type -MemberDefinition '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);' -name Win32ShowWindowAsync -namespace Win32Functions -PassThru)::ShowWindowAsync((Get-Process -PID $pid).MainWindowHandle, 0) }

[System.Windows.Forms.Screen]::PrimaryScreen | Out-Null

[xml]$XAMLMainWindow = @"
<Window x:Name="Window_Main"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        Title="TrayToy" Height="217" Width="200" ResizeMode="NoResize" WindowStyle="None" SnapsToDevicePixels="True"  BorderThickness="1" BorderBrush="{DynamicResource {x:Static SystemColors.ControlDarkBrushKey}}" Background="#FFCBCBCB" Topmost="{Binding ElementName=CheckBox_AkwaysOnTop, Path=IsChecked}" AllowsTransparency="True" Opacity="{Binding ElementName=Slider_Opacity, Path=Value}" Focusable="True" ShowInTaskbar="False">
    <Grid x:Name="WindowMain_Grid">
        <Grid.RowDefinitions>
            <RowDefinition Height = "25*" />
            <RowDefinition Height = "66*" />
            <RowDefinition Height = "24*" />
            <RowDefinition Height = "4*" />
            <RowDefinition Height = "26*" />
            <RowDefinition Height = "50*" />
            <RowDefinition Height = "21*" />
        </Grid.RowDefinitions>

        <Grid Grid.Row = "0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="129*"/>
                <ColumnDefinition Width="20*"/>
            </Grid.ColumnDefinitions>

            <Label x:Name="Label_SetCPUMaxSpeed" Content="Set CPU Max Speed / Freq.:" HorizontalAlignment="Left"/>
            <Button x:Name="Button_Hide" Grid.Column = "1" HorizontalAlignment="Center" VerticalAlignment="Top" BorderBrush="#FFE6E6E6" Height="22" Width="22">
                <Grid Height="16" Width="16" HorizontalAlignment="Center">
                    <Rectangle Fill="#FFF4F4F5" HorizontalAlignment="Left" Height="2" Width="17" Margin="0,14,0,0" Stroke="Black" VerticalAlignment="Top"/>
                </Grid>
            </Button>
        </Grid>

        <Grid Grid.Row = "1">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="25*"/>
                <ColumnDefinition Width="28*"/>
                <ColumnDefinition Width="24*"/>
                <ColumnDefinition Width="42*"/>
                <ColumnDefinition Width="52*"/>
                <ColumnDefinition Width="26*"/>
            </Grid.ColumnDefinitions>

            <StackPanel x:Name="StackPanel_CPU" Grid.Column = "0">
                <Grid>
                    <Grid.RowDefinitions>
                        <RowDefinition/>
                        <RowDefinition/>
                        <RowDefinition/>
                        <RowDefinition/>
                    </Grid.RowDefinitions>

                    <RadioButton x:Name="RadioButton_CPU_1" Grid.Row = "0" HorizontalAlignment="Center" VerticalAlignment="Center" Height="16"/>
                    <RadioButton x:Name="RadioButton_CPU_2" Grid.Row = "1" HorizontalAlignment="Center" VerticalAlignment="Center" Height="17"/>
                    <RadioButton x:Name="RadioButton_CPU_3" Grid.Row = "2" HorizontalAlignment="Center" VerticalAlignment="Center" Height="16"/>
                    <RadioButton x:Name="RadioButton_CPU_4" Grid.Row = "3" HorizontalAlignment="Center" VerticalAlignment="Center" Height="17"/>

                </Grid>
            </StackPanel>

            <Grid Grid.ColumnSpan="2" Margin="25,0,0,0">
                <Grid.RowDefinitions>
                    <RowDefinition Height = "*" />
                    <RowDefinition Height = "*" />
                    <RowDefinition Height = "*" />
                    <RowDefinition Height = "*" />
                </Grid.RowDefinitions>
                <Label x:Name="Label_CPU_1" Content="25" HorizontalAlignment="Center" VerticalAlignment="Center" Margin="0,-7,0,0"/>
                <TextBox x:Name="TextBox_CPU_2" HorizontalAlignment="Center" Grid.Row="1" TextWrapping="Wrap" VerticalAlignment="Center" Width="27" HorizontalContentAlignment="Center" Margin="-1,-2,0,0"/>
                <TextBox x:Name="TextBox_CPU_3" HorizontalAlignment="Center" Grid.Row="2" TextWrapping="Wrap" VerticalAlignment="Center" Width="27" HorizontalContentAlignment="Center" Margin="-1,-2,0,0"/>
                <Label x:Name="Label_CPU_4" Content="100" Grid.Row="3"  VerticalAlignment="Top" Margin="-3,-7,0,0" Width="50" HorizontalAlignment="Left"/>

            </Grid>

            <Grid Grid.Column = "1" Grid.ColumnSpan="2" Margin="25,0,0,0">
                <Grid.RowDefinitions>
                    <RowDefinition Height = "*" />
                    <RowDefinition Height = "*" />
                    <RowDefinition Height = "*" />
                    <RowDefinition Height = "*" />
                </Grid.RowDefinitions>
                <Label Grid.Row="0" Content="% / " HorizontalAlignment="Left" VerticalAlignment="Center" Margin="0,-7,0,0"/>
                <Label Grid.Row="1" Content="% / " HorizontalAlignment="Left" VerticalAlignment="Center" Margin="0,-7,0,0"/>
                <Label Grid.Row="2" Content="% / " HorizontalAlignment="Left" VerticalAlignment="Center" Margin="0,-7,0,0"/>
                <Label Grid.Row="3" Content="% / " HorizontalAlignment="Left" VerticalAlignment="Center" Margin="0,-7,0,0"/>
            </Grid>

            <Grid Grid.Column = "3" Margin="2,0,3,0">
                <Grid.RowDefinitions>
                    <RowDefinition Height = "*" />
                    <RowDefinition Height = "*" />
                    <RowDefinition Height = "*" />
                    <RowDefinition Height = "*" />
                </Grid.RowDefinitions>

                <Label x:Name="Label_CPUFreq_1" Grid.Row="0" HorizontalAlignment="Left" VerticalAlignment="Center" Margin="0,-7,0,0"/>
                <Label x:Name="Label_CPUFreq_2" Grid.Row="1" HorizontalAlignment="Left" VerticalAlignment="Center" Margin="0,-7,0,0"/>
                <Label x:Name="Label_CPUFreq_3" Grid.Row="2" HorizontalAlignment="Left" VerticalAlignment="Center" Margin="0,-7,0,0"/>
                <Label x:Name="Label_CPUFreq_4" Grid.Row="3" HorizontalAlignment="Left" VerticalAlignment="Center" Margin="0,-7,0,0"/>
            </Grid>

            <Grid Grid.Column = "4" Grid.ColumnSpan="2" Margin="0,0,26,0">
                <Grid.RowDefinitions>
                    <RowDefinition Height = "*" />
                    <RowDefinition Height = "*" />
                    <RowDefinition Height = "*" />
                    <RowDefinition Height = "*" />
                </Grid.RowDefinitions>

                <Label Grid.Row="0" Content="GHz" HorizontalAlignment="Left" VerticalAlignment="Center" Margin="0,-7,0,0"/>
                <Label Grid.Row="1" Content="GHz" HorizontalAlignment="Left" VerticalAlignment="Center" Margin="0,-7,0,0"/>
                <Label Grid.Row="2" Content="GHz" HorizontalAlignment="Left" VerticalAlignment="Center" Margin="0,-7,0,0"/>
                <Label Grid.Row="3" Content="GHz" HorizontalAlignment="Left" VerticalAlignment="Center" Margin="0,-7,0,0"/>
            </Grid>

            <CheckBox x:Name="CheckBox_AutoRun" Grid.Column="5" HorizontalAlignment="Center" VerticalAlignment="Top" Height="15" Width="16">
                <CheckBox.ToolTip>
                    <ToolTip Background="{DynamicResource {x:Static SystemColors.InfoBrushKey}}">AutoRun at Logon</ToolTip>
                </CheckBox.ToolTip>
            </CheckBox>

        </Grid>

        <Grid Grid.Row = "2">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="55*"/>
                <ColumnDefinition Width="30*"/>
                <ColumnDefinition Width="28*"/>
                <ColumnDefinition Width="32*"/>
                <ColumnDefinition Width="53*"/>
            </Grid.ColumnDefinitions>
            <Label Content="Currrent:" Grid.Column="0"/>
            <Label x:Name="Label_CPU_Current" Grid.Column="1"/>
            <Label Content="% /" Grid.Column="2"/>
            <Label x:Name="Label_Frequency_Current" Grid.Column="3"/>
            <Label Grid.Column="4" Content="GHz"/>
        </Grid>

        <Grid Grid.Row = "3">
            <Border BorderBrush="#FFE6E6E6" BorderThickness="2" Height="4" HorizontalAlignment="Center" Width="170" VerticalAlignment="Center"/>
        </Grid>

        <Label Content="Set Display Standby Time:" HorizontalAlignment="Left" Grid.Row="4" Width="177"/>

        <Grid Grid.Row="5">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="14*"/>
                <ColumnDefinition Width="21*"/>
                <ColumnDefinition Width="64*"/>
            </Grid.ColumnDefinitions>

            <StackPanel x:Name="StackPanel_DisplayStandby">
                <RadioButton x:Name="RadioButton_DisplayStandby_1" HorizontalAlignment="Center"/>
                <RadioButton x:Name="RadioButton_DisplayStandby_2" HorizontalAlignment="Center"/>
                <RadioButton x:Name="RadioButton_DisplayStandby_3" HorizontalAlignment="Center"/>
            </StackPanel>

            <Grid Grid.Column="1">
                <Grid.RowDefinitions>
                    <RowDefinition Height = "*" />
                    <RowDefinition Height = "*" />
                    <RowDefinition Height = "*" />
                </Grid.RowDefinitions>
                <Label x:Name="Label_DisplayStandby_1" Content="1" HorizontalAlignment="Left" Margin="0,-7,0,0"/>
                <TextBox x:Name="TextBox_DisplayStandby_2" HorizontalAlignment="Left" Grid.Row="1" VerticalAlignment="Top" Width="40" Margin="0,-3,0,0"/>
                <Label x:Name="Label_DisplayStandby_3" Content="0" HorizontalAlignment="Left" Grid.Row="2" VerticalAlignment="Center" Margin="0,-8,0,0"/>


            </Grid>

            <Grid Grid.Column="2">
                <Grid.RowDefinitions>
                    <RowDefinition Height = "*" />
                    <RowDefinition Height = "*" />
                    <RowDefinition Height = "*" />
                </Grid.RowDefinitions>
                <Label Content="min" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="0,-7,0,0"/>
                <Label Content="min" HorizontalAlignment="Left" Grid.Row="1" VerticalAlignment="Top" Margin="0,-8,0,0"/>
                <Label Content="Never" HorizontalAlignment="Left" Grid.Row="2" VerticalAlignment="Top" Margin="0,-8,0,0"/>

            </Grid>

        </Grid>

        <Grid Grid.Row="6">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="17*"/>
                <ColumnDefinition Width="5*"/>
            </Grid.ColumnDefinitions>

            <Label Content="Current Standby Time, min:" VerticalAlignment="Top" Height="25" Margin="0,-2,0,0"/>
            <Label x:Name="Label_CurrentStandbyTime" Grid.Column="1" VerticalAlignment="Top" Margin="0,-2,0,0"/>

        </Grid>

    </Grid>
</Window>
"@
$Reader=(New-Object System.Xml.XmlNodeReader $XAMLMainWindow)
try { $Window_main = [Windows.Markup.XamlReader]::Load($Reader) } catch { Write-Warning $_.Exception ; throw }
$XAMLMainWindow.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | % { New-Variable  -Name $_.Name -Value $Window_main.FindName($_.Name) -Force -ErrorAction SilentlyContinue}

$Scale = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Width/[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width

# Подготовка значений для активных элементов окна
Try { if (Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $appName) {$CheckBox_AutoRun.IsChecked = $true} } catch {}

$ExecDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('.\')
$iniFilePath = $ExecDir + "\" + $appName + ".ini"

Try {
    $iniFile = Get-Content -Path $iniFilePath -ErrorAction SilentlyContinue
    if ($iniFile | ? {$_ -like "TextBox_CPU_2*"}) {$TextBox_CPU_2.Text = (($iniFile | ? {$_ -like "TextBox_CPU_2*"}) -split " ")[1]} else {$TextBox_CPU_2.Text = 50}
    if ($iniFile | ? {$_ -like "TextBox_CPU_3*"}) {$TextBox_CPU_3.Text = (($iniFile | ? {$_ -like "TextBox_CPU_3*"}) -split " ")[1]} else {$TextBox_CPU_3.Text = 75}
    if ($iniFile | ? {$_ -like "TextBox_DisplayStandBy_2*"}) {$TextBox_DisplayStandBy_2.Text = (($iniFile | ? {$_ -like "TextBox_DisplayStandBy_2*"}) -split " ")[1]} else {$TextBox_DisplayStandBy_2.Text = 15}
} catch {
    $TextBox_CPU_2.Text = 50
    $TextBox_CPU_3.Text = 75
    $TextBox_DisplayStandBy_2.Text = 15
}

$CPUMaxSpeedGHz = [math]::Round((Get-CimInstance Win32_Processor | Select-Object -Expand MaxClockSpeed)/1000,2)
$Label_CPUFreq_1.Content = $CPUMaxSpeedGHz*0.25
$Label_CPUFreq_2.Content = $CPUMaxSpeedGHz*([Convert]::ToInt32($TextBox_CPU_2.Text, 10))/100
$Label_CPUFreq_3.Content = $CPUMaxSpeedGHz*([Convert]::ToInt32($TextBox_CPU_3.Text, 10))/100
$Label_CPUFreq_4.Content = $CPUMaxSpeedGHz

# Чтение параметров активного плана и установка RadioButtons по актуальным значениям, либо сброс, если нет соответствий
$SetRadioButtons = {
    $Global:PowerSchemeID = (powercfg /getactivescheme).Split(" ") | ? {$_ -like "*-*"}
    $POWERCFG_ALIASES = POWERCFG /ALIASES
    $Global:SUB_PROCESSOR_ID =  (($POWERCFG_ALIASES | ? {$_ -like "*SUB_PROCESSOR"}).Split(" "))[0]
    $Global:PROCTHROTTLEMaxID = (($POWERCFG_ALIASES | ? {$_ -like "*PROCTHROTTLEMAX"}).Split(" "))[0]
    $PowerScheme = powercfg /QUERY $Global:PowerSchemeID
    $ActiveCPUMax_Str = $PowerScheme[$($PowerScheme.IndexOf($($PowerScheme | ? {$_ -like ("*" + $Global:PROCTHROTTLEMaxID + "*")})) + 6)] -split " "
    $ActiveCPUMax = [Convert]::ToInt32($((($ActiveCPUMax_Str[-1] -split "x")[1]).TrimStart("0")), 16)
    $Label_CPU_Current.Content = $ActiveCPUMax
    $Label_Frequency_Current.Content = $CPUMaxSpeedGHz*($ActiveCPUMax)/100
    $MatchedIndex = ($Label_CPU_1.Content,$TextBox_CPU_2.Text,$TextBox_CPU_3.Text,$Label_CPU_4.Content).IndexOf($ActiveCPUMax.ToString())
    Switch ($MatchedIndex) {
        {@(0..3) -contains $_} {(Get-Variable -Name $("RadioButton_CPU_" + ($_ + 1))).Value.IsChecked = $true}
        DEFAULT {
            "1,2,3,4" -split "," | % { (Get-Variable -Name $("RadioButton_CPU_" + $_)).Value.IsChecked = $false }
        }
    }

    $Global:SUB_VIDEO = (($POWERCFG_ALIASES | ? {$_ -like "*SUB_VIDEO"}).Split(" "))[0]
    $Global:VIDEOIDLE = (($POWERCFG_ALIASES | ? {$_ -like "*VIDEOIDLE"}).Split(" "))[0]
    $ActiveStandBy_Str = $PowerScheme[$($PowerScheme.IndexOf($($PowerScheme | ? {$_ -like ("*" + $Global:VIDEOIDLE + "*")})) + 6)] -split " "
    $ActiveStandBy = [Convert]::ToInt32($((($ActiveStandBy_Str[-1] -split "x")[1])), 16)
    $MatchedIndex = ($Label_DisplayStandBy_1.Content,$TextBox_DisplayStandBy_2.Text,$Label_DisplayStandBy_3.Content).IndexOf(($ActiveStandBy/60).ToString())
    $Label_CurrentStandbyTime.Content = $ActiveStandBy/60

    Switch ($MatchedIndex) {
        {@(0..2) -contains $_} {(Get-Variable -Name $("RadioButton_DisplayStandby_" + ($_ + 1))).Value.IsChecked = $true}
        DEFAULT {
            "1,2,3" -split "," | % { (Get-Variable -Name $("RadioButton_DisplayStandby_" + $_)).Value.IsChecked = $false }
        }
    } 
}

# Обработка событий чекбокса AutoRun at Logon
$CheckBox_AutoRun.Add_Checked({ New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $appName -Value $("cmd /c " + $([char]'"') + "Start /D $ExecDir powershell -WindowStyle hidden -file $ExecDir\" + $appName + ".ps1" + $([char]'"')) ; SaveConfiguration})

#cmd /c "Start /D c:\Scripts\TrayToy powershell -WindowStyle hidden -file "C:\Scripts\TrayToy\TrayToy.ps1"
$CheckBox_AutoRun.Add_UnChecked({ Remove-ItemProperty  -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $appName ; SaveConfiguration })

# Обработка событий RadioButton_CPU
[System.Windows.RoutedEventHandler]$Script:CheckedEventHandlerCPU = {
    $ChoiceIndex = ($_.source.name).Replace("RadioButton_CPU_","")
    Switch ($ChoiceIndex) {
        "1" {
            powercfg /SETACVALUEINDEX $Global:PowerSchemeID $Global:SUB_PROCESSOR_ID $Global:PROCTHROTTLEMaxID 25
            $Label_CPU_Current.Content = 25
        }
        "2" {
            powercfg /SETACVALUEINDEX $Global:PowerSchemeID $Global:SUB_PROCESSOR_ID $Global:PROCTHROTTLEMaxID $TextBox_CPU_2.Text
            $Label_CPU_Current.Content = $TextBox_CPU_2.Text
        }
        "3" {
            powercfg /SETACVALUEINDEX $Global:PowerSchemeID $Global:SUB_PROCESSOR_ID $Global:PROCTHROTTLEMaxID $TextBox_CPU_3.Text
            $Label_CPU_Current.Content = $TextBox_CPU_3.Text
        }
        "4" {
            powercfg /SETACVALUEINDEX $Global:PowerSchemeID $Global:SUB_PROCESSOR_ID $Global:PROCTHROTTLEMaxID 100
            $Label_CPU_Current.Content = 100
        }
    }
    $Label_Frequency_Current.Content = $CPUMaxSpeedGHz*([Convert]::ToInt32($Label_CPU_Current.Content, 10))/100
    powercfg /setactive $Global:PowerSchemeID
    SaveConfiguration
}
$StackPanel_CPU.AddHandler([System.Windows.Controls.RadioButton]::CheckedEvent, $CheckedEventHandlerCPU)

# Обработка событий RadioButton_DisplayStandBy
[System.Windows.RoutedEventHandler]$Script:CheckedEventHandlerDisplayStandBy = {
    $ChoiceIndex = ($_.source.name).Replace("RadioButton_DisplayStandby_","")
    Switch ($ChoiceIndex) {
        "1" {
            powercfg /SETACVALUEINDEX $Global:PowerSchemeID $Global:SUB_VIDEO $Global:VIDEOIDLE 60
            $Label_CurrentStandbyTime.Content = 1
        }
        "2" {
            powercfg /SETACVALUEINDEX $Global:PowerSchemeID $Global:SUB_VIDEO $Global:VIDEOIDLE $([int]$TextBox_DisplayStandBy_2.Text * 60)
            $Label_CurrentStandbyTime.Content = $TextBox_DisplayStandBy_2.Text
        }
        "3" {
            powercfg /SETACVALUEINDEX $Global:PowerSchemeID $Global:SUB_VIDEO $Global:VIDEOIDLE 0
            $Label_CurrentStandbyTime.Content = 0
        }
    }
    powercfg /setactive $Global:PowerSchemeID
    SaveConfiguration
}
$StackPanel_DisplayStandby.AddHandler([System.Windows.Controls.RadioButton]::CheckedEvent, $CheckedEventHandlerDisplayStandBy)

# Фильтр ввода для TextBox_CPU_2, переключение режима при изменении величины
$TextBox_CPU_2.Add_PreviewKeyDown({
    param
    (
      [Parameter(Mandatory)][Object]$sender,
      [Parameter(Mandatory)][Windows.Input.KeyEventArgs]$e
    )

    #[System.Windows.MessageBox]::Show($e.Key)
    if ("Delete","Return","Back","D0","D1","D2","D3","D4","D5","D6","D7","D8","D9","NumPad0","NumPad1","NumPad2","NumPad3","NumPad4","NumPad5","NumPad6","NumPad7","NumPad8","NumPad9","Left","Right","Home","End" -notcontains $e.Key) {$e.Handled = $true}
    
    if ($e.Key -eq "Return") {
        if ([int]$TextBox_CPU_2.Text -lt 25) {$TextBox_CPU_2.Text = "25"}
        if ([int]$TextBox_CPU_2.Text -gt 100) {$TextBox_CPU_2.Text = "100"}
        $Label_CPUFreq_2.Content = $CPUMaxSpeedGHz*([Convert]::ToInt32($TextBox_CPU_2.Text, 10))/100
        if ($RadioButton_CPU_2.IsChecked) {
            powercfg /SETACVALUEINDEX $Global:PowerSchemeID $Global:SUB_PROCESSOR_ID $Global:PROCTHROTTLEMaxID $TextBox_CPU_2.Text
            $Label_CPU_Current.Content = $TextBox_CPU_2.Text
            $Label_Frequency_Current.Content = $CPUMaxSpeedGHz*([int]$Label_CPU_Current.Content)/100
        }
    }
})

$TextBox_CPU_2.Add_LostFocus({
    
})

$TextBox_CPU_2.Add_TextChanged({
    #if ([int]$TextBox_CPU_2.Text -lt 25) {$TextBox_CPU_2.Text = "26"}
    #if ([int]$TextBox_CPU_2.Text -gt 100) {$TextBox_CPU_2.Text = "99"}
    $Label_CPUFreq_2.Content = $CPUMaxSpeedGHz*([Convert]::ToInt32($TextBox_CPU_2.Text, 10))/100
    if ($RadioButton_CPU_2.IsChecked) {
        powercfg /SETACVALUEINDEX $Global:PowerSchemeID $Global:SUB_PROCESSOR_ID $Global:PROCTHROTTLEMaxID $TextBox_CPU_2.Text
        $Label_CPU_Current.Content = $TextBox_CPU_2.Text
        $Label_Frequency_Current.Content = $CPUMaxSpeedGHz*([int]$Label_CPU_Current.Content)/100
    }
    SaveConfiguration
})

# Фильтр ввода для TextBox_CPU_3, переключение режима при изменении величины
$TextBox_CPU_3.Add_PreviewKeyDown({
    param
    (
      [Parameter(Mandatory)][Object]$sender,
      [Parameter(Mandatory)][Windows.Input.KeyEventArgs]$e
    )

    #[System.Windows.MessageBox]::Show($e.Key)
    if ("Delete","Return","Back","D0","D1","D2","D3","D4","D5","D6","D7","D8","D9","NumPad0","NumPad1","NumPad2","NumPad3","NumPad4","NumPad5","NumPad6","NumPad7","NumPad8","NumPad9","Left","Right","Home","End" -notcontains $e.Key) {$e.Handled = $true}
    
    if ($e.Key -eq "Return") {
        if ([int]$TextBox_CPU_3.Text -lt 25) {$TextBox_CPU_3.Text = "26"}
        if ([int]$TextBox_CPU_3.Text -gt 100) {$TextBox_CPU_3.Text = "99"}
        $Label_CPUFreq_3.Content = $CPUMaxSpeedGHz*([Convert]::ToInt32($TextBox_CPU_3.Text, 10))/100
        if ($RadioButton_CPU_3.IsChecked) {
            powercfg /SETACVALUEINDEX $Global:PowerSchemeID $Global:SUB_PROCESSOR_ID $Global:PROCTHROTTLEMaxID $TextBox_CPU_3.Text
            $Label_CPU_Current.Content = $TextBox_CPU_3.Text
            $Label_Frequency_Current.Content = $CPUMaxSpeedGHz*([int]$Label_CPU_Current.Content)/100
        }
    }
})

$TextBox_CPU_3.Add_LostFocus({

})

$TextBox_CPU_3.Add_TextChanged({
    #if ([int]$TextBox_CPU_3.Text -lt 25) {$TextBox_CPU_3.Text = "25"}
    #if ([int]$TextBox_CPU_3.Text -gt 100) {$TextBox_CPU_3.Text = "100"}
    $Label_CPUFreq_3.Content = $CPUMaxSpeedGHz*([Convert]::ToInt32($TextBox_CPU_3.Text, 10))/100
    if ($RadioButton_CPU_3.IsChecked) {
        powercfg /SETACVALUEINDEX $Global:PowerSchemeID $Global:SUB_PROCESSOR_ID $Global:PROCTHROTTLEMaxID $TextBox_CPU_3.Text
        $Label_CPU_Current.Content = $TextBox_CPU_3.Text
        $Label_Frequency_Current.Content = $CPUMaxSpeedGHz*([int]$Label_CPU_Current.Content)/100
    }
    SaveConfiguration
})

# Фильтр ввода для TextBox_DisplayStandby_2, переключение режима при изменении величины
$TextBox_DisplayStandby_2.Add_PreviewKeyDown({
    param
    (
      [Parameter(Mandatory)][Object]$sender,
      [Parameter(Mandatory)][Windows.Input.KeyEventArgs]$e
    )

    #[System.Windows.MessageBox]::Show($e.Key)
    if ("Delete","Return","Back","D0","D1","D2","D3","D4","D5","D6","D7","D8","D9","NumPad0","NumPad1","NumPad2","NumPad3","NumPad4","NumPad5","NumPad6","NumPad7","NumPad8","NumPad9","Left","Right","Home","End" -notcontains $e.Key) {$e.Handled = $true}
    
    if ($e.Key -eq "Return") {
        if ([int]$TextBox_DisplayStandby_2.Text -le 1) {$TextBox_DisplayStandby_2.Text = "2"}
        if ($RadioButton_DisplayStandby_2.IsChecked) {
            powercfg /SETACVALUEINDEX $Global:PowerSchemeID $Global:SUB_VIDEO $Global:VIDEOIDLE $([int]$TextBox_DisplayStandBy_2.Text * 60)
            $Label_CurrentStandbyTime.Content = $TextBox_DisplayStandBy_2.Text
        }
    }
})

$TextBox_DisplayStandby_2.Add_LostFocus({
    
})

$TextBox_DisplayStandby_2.Add_TextChanged({
    #if ([int]$TextBox_DisplayStandby_2.Text -le 1) {$TextBox_DisplayStandby_2.Text = "1"}
    if ($RadioButton_DisplayStandby_2.IsChecked) {
        powercfg /SETACVALUEINDEX $Global:PowerSchemeID $Global:SUB_VIDEO $Global:VIDEOIDLE $([int]$TextBox_DisplayStandBy_2.Text * 60)
        $Label_CurrentStandbyTime.Content = $TextBox_DisplayStandBy_2.Text
    }
    SaveConfiguration
})

$Window_main.Title += " v." + $appVersion

$Window_main.Add_Deactivated({ $Window_main.Hide() ; SaveConfiguration})

## Ported Code forming System Tray Icon
## https://gist.github.com/selvalogesh/37b99e43b932d42b5a9901a33284b4fa

[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')       | out-null
[System.Reflection.Assembly]::LoadWithPartialName('presentationframework')      | out-null
[System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')          | out-null
[System.Reflection.Assembly]::LoadWithPartialName('WindowsFormsIntegration') | out-null

$icon = [System.Drawing.Icon]::ExtractAssociatedIcon("C:\Windows\System32\EaseOfAccessDialog.exe")    

$Main_Tool_Icon = New-Object System.Windows.Forms.NotifyIcon
$Main_Tool_Icon.Text = $appName + " v." + $appVersion
$Main_Tool_Icon.Icon = $icon
$Main_Tool_Icon.Visible = $true

$Menu_Exit = New-Object System.Windows.Forms.MenuItem
$Menu_Exit.Text = "Exit"

$contextmenu = New-Object System.Windows.Forms.ContextMenu
$Main_Tool_Icon.ContextMenu = $contextmenu
$Main_Tool_Icon.contextMenu.MenuItems.AddRange($Menu_Exit)

$Main_Tool_Icon.Add_Click({                    
    If ($_.Button -eq [Windows.Forms.MouseButtons]::Right) {
        $Main_Tool_Icon.GetType().GetMethod("ShowContextMenu",[System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic).Invoke($Main_Tool_Icon,$null)
    } else {
        #$Scale = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Width/[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width
        Invoke-Command -ScriptBlock $SetRadioButtons
        $TaskBarHeight = [System.Windows.Forms.SystemInformation]::VirtualScreen.Height - [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Height
        $Window_main.Top = ([System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Height)/$Scale - $Window_main.Height
        $Window_main.Left = ([System.Windows.Forms.Cursor]::Position.X)/$Scale - $Window_main.Width/2
        $Window_main.Activate() | Out-Null
        $Window_main.Focus()
        $Window_main.ShowDialog()
    }
})

# Обработка клика Button_Hide
$Button_Hide.add_Click.Invoke({ $Window_main.Hide() ; SaveConfiguration})

Function SaveConfiguration {
    "This is config file for TrayToy Application`r`n`r`nTextBox_CPU_2: $($TextBox_CPU_2.Text)`r`nTextBox_CPU_3: $($TextBox_CPU_3.Text)`r`nTextBox_DisplayStandBy_2: $($TextBox_DisplayStandBy_2.Text)" | Out-File -FilePath $iniFilePath
}

# When Exit is clicked, close everything and kill the PowerShell process
$Menu_Exit.add_Click({
    SaveConfiguration
    $Window_main.Close()
    #Stop-Process $pid
    [Environment]::Exit(1)
})

# Force garbage collection just to start slightly lower RAM usage.
[System.GC]::Collect()

# Create an application context for it to all run within.
# This helps with responsiveness, especially when clicking Exit.
$appContext = New-Object System.Windows.Forms.ApplicationContext
[void][System.Windows.Forms.Application]::Run($appContext)