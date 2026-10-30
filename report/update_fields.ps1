param([string]$Docx, [string]$PngPrefix = "", [string]$PngDir = "")
# Opens the report in a SEPARATE hidden Word instance, updates the contents / list of figures / list of tables, saves, optionally exports page PNGs.
# Never touches the user's own Word windows: identifies its own process by comparing process ids before and after.
$before = @(Get-Process WINWORD -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
$word = New-Object -ComObject Word.Application
$word.Visible = $false; $word.DisplayAlerts = 0
$mine = @(Get-Process WINWORD -ErrorAction SilentlyContinue | Where-Object { $before -notcontains $_.Id } | ForEach-Object { $_.Id })
try {
  $doc = $word.Documents.Open($Docx, $false, $false)
  foreach ($sid in -20, -21, -22, -36) {   # built-in TOC 1-3 and Table of Figures styles: single spacing, small gap
    $st = $doc.Styles.Item($sid); $st.ParagraphFormat.LineSpacingRule = 0; $st.ParagraphFormat.SpaceAfter = 4; $st.ParagraphFormat.SpaceBefore = 0
  }
  $doc.Repaginate()
  foreach ($t in @($doc.TablesOfContents)) { $t.Update() }
  foreach ($t in @($doc.TablesOfFigures)) { $t.Update() }
  $doc.Fields.Update() | Out-Null
  foreach ($t in @($doc.TablesOfContents)) { $t.Update() }
  foreach ($t in @($doc.TablesOfFigures)) { $t.Update() }
  $doc.Save()
  $n = $doc.ComputeStatistics(2)
  "pages: $n"
  if ($PngDir) {
    Add-Type -AssemblyName System.Drawing
    New-Item -ItemType Directory -Force $PngDir | Out-Null
    $win = $doc.Windows.Item(1); $win.View.Type = 3
    foreach ($i in 1..$n) {
      $bytes = $win.Panes.Item(1).Pages.Item($i).EnhMetaFileBits
      $ms = New-Object IO.MemoryStream(,$bytes); $mf = New-Object Drawing.Imaging.Metafile($ms)
      $bmp = New-Object Drawing.Bitmap(900, 1273); $g = [Drawing.Graphics]::FromImage($bmp)
      $g.Clear([Drawing.Color]::White); $g.InterpolationMode = 'HighQualityBicubic'; $g.DrawImage($mf, 0, 0, 900, 1273)
      $bmp.Save("$PngDir\$PngPrefix$i.png", [Drawing.Imaging.ImageFormat]::Png)
      $g.Dispose(); $bmp.Dispose(); $mf.Dispose(); $ms.Dispose()
    }
  }
  $doc.Close($false)
} finally {
  try { $word.Quit() } catch {}
  Start-Sleep -Seconds 2
  foreach ($id in $mine) { if (Get-Process -Id $id -ErrorAction SilentlyContinue) { Stop-Process -Id $id -Force } }
}
