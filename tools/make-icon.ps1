# Generates Cda.App\app.ico — the "CDA" monogram in the app's palette.
# Amber letters (#E0B341) on a rounded deep-slate tile, rendered at every
# icon size and packed into a single multi-resolution .ico (PNG-compressed
# entries). Also drops preview PNGs for eyeballing. Re-runnable.

Add-Type -AssemblyName System.Drawing

$ErrorActionPreference = 'Stop'

$outIco   = Join-Path $PSScriptRoot '..\Cda.App\app.ico'
$previewDir = $PSScriptRoot
$sizes    = 16,24,32,48,64,128,256

# --- palette (matches Visualization\VisualTheme.cs / App.xaml) -------------
$amber    = [System.Drawing.Color]::FromArgb(0xE0,0xB3,0x41)
$tileTop  = [System.Drawing.Color]::FromArgb(0x1C,0x23,0x2D)  # slightly lifted so the tile
$tileBot  = [System.Drawing.Color]::FromArgb(0x11,0x16,0x1D)  # reads against a black taskbar
$border   = [System.Drawing.Color]::FromArgb(0x32,0x3C,0x4A)

function New-RoundedPath([float]$x,[float]$y,[float]$w,[float]$h,[float]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $r * 2
    $p.AddArc($x,            $y,            $d, $d, 180, 90)
    $p.AddArc($x + $w - $d,  $y,            $d, $d, 270, 90)
    $p.AddArc($x + $w - $d,  $y + $h - $d,  $d, $d,   0, 90)
    $p.AddArc($x,            $y + $h - $d,  $d, $d,  90, 90)
    $p.CloseFigure()
    return $p
}

function Render-Size([int]$s) {
    $bmp = New-Object System.Drawing.Bitmap($s, $s, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode     = 'AntiAlias'
    $g.InterpolationMode = 'HighQualityBicubic'
    $g.TextRenderingHint = 'AntiAliasGridFit'
    $g.Clear([System.Drawing.Color]::Transparent)

    # Rounded tile, inset a hair so the corners + border aren't clipped.
    [single]$inset  = [Math]::Max(1.0, $s * 0.03)
    [single]$radius = $s * 0.22
    [single]$tw = $s - 2*$inset
    $path = New-RoundedPath $inset $inset $tw $tw $radius

    $rect = New-Object System.Drawing.RectangleF($inset, $inset, $tw, $tw)
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, $tileTop, $tileBot, 90.0)
    $g.FillPath($grad, $path)

    $penW = [Math]::Max(1.0, $s/64.0)
    $pen  = New-Object System.Drawing.Pen($border, $penW)
    $g.DrawPath($pen, $path)

    # "CDA" — fit the width, optical-centre it, amber. Use typographic string
    # format so GDI+ padding doesn't throw off the centring/scale.
    $fmt = [System.Drawing.StringFormat]::GenericTypographic
    $fmt.Alignment     = 'Center'
    $fmt.LineAlignment = 'Center'

    $text   = 'CDA'
    $target = $tw * 0.78          # letters span ~78% of the tile
    $fsize  = $s * 0.42
    $font   = New-Object System.Drawing.Font('Segoe UI Black', $fsize, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $meas   = $g.MeasureString($text, $font, [int][Math]::Ceiling($s*2), $fmt)
    if ($meas.Width -gt 0) {
        $scale = $target / $meas.Width
        $fsize = $fsize * $scale
        # don't let it get too tall on the 3-letter block
        $maxH = $tw * 0.52
        $reh  = $meas.Height * $scale
        if ($reh -gt $maxH) { $fsize = $fsize * ($maxH / $reh) }
        $font.Dispose()
        $font = New-Object System.Drawing.Font('Segoe UI Black', $fsize, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    }

    # nudge the text up a touch to sit above a thin amber accent rule
    [single]$ty = $inset - ($s * 0.04)
    $textRect = New-Object System.Drawing.RectangleF($inset, $ty, $tw, $tw)
    $amberBrush = New-Object System.Drawing.SolidBrush($amber)
    $g.DrawString($text, $font, $amberBrush, $textRect, $fmt)

    # thin amber accent rule under the monogram (skip at the tiniest size where
    # it would just muddy the letters)
    if ($s -ge 24) {
        [single]$barW = $tw * 0.46
        [single]$barH = [Math]::Max(1.0, $s/24.0)
        [single]$barX = $inset + (($tw - $barW)/2.0)
        [single]$barY = $inset + ($tw * 0.74)
        $g.FillRectangle($amberBrush, $barX, $barY, $barW, $barH)
    }

    $g.Dispose(); $grad.Dispose(); $pen.Dispose(); $amberBrush.Dispose(); $font.Dispose(); $path.Dispose()
    return $bmp
}

# Render every size, capture PNG bytes.
$pngs = @{}
foreach ($s in $sizes) {
    $bmp = Render-Size $s
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngs[$s] = $ms.ToArray()
    if ($s -eq 256 -or $s -eq 32) {
        $bmp.Save((Join-Path $previewDir "icon-preview-$s.png"), [System.Drawing.Imaging.ImageFormat]::Png)
    }
    $ms.Dispose(); $bmp.Dispose()
}

# --- write the .ico (ICONDIR + ICONDIRENTRY[] + PNG payloads) --------------
$fs = [System.IO.File]::Create((Resolve-Path -LiteralPath (Split-Path $outIco)).Path + '\' + (Split-Path $outIco -Leaf))
$bw = New-Object System.IO.BinaryWriter($fs)
$bw.Write([UInt16]0)            # reserved
$bw.Write([UInt16]1)            # type = icon
$bw.Write([UInt16]$sizes.Count) # image count

$offset = 6 + 16*$sizes.Count   # header + all dir entries
foreach ($s in $sizes) {
    $data = $pngs[$s]
    $dim = if ($s -ge 256) { 0 } else { $s }   # 0 means 256 in the dir entry
    $bw.Write([Byte]$dim)       # width
    $bw.Write([Byte]$dim)       # height
    $bw.Write([Byte]0)          # palette count
    $bw.Write([Byte]0)          # reserved
    $bw.Write([UInt16]1)        # planes
    $bw.Write([UInt16]32)       # bit depth
    $bw.Write([UInt32]$data.Length)
    $bw.Write([UInt32]$offset)
    $offset += $data.Length
}
foreach ($s in $sizes) { $bw.Write($pngs[$s]) }
$bw.Flush(); $bw.Close(); $fs.Close()

Write-Host ("Wrote {0} ({1:N0} bytes), sizes: {2}" -f $outIco, (Get-Item $outIco).Length, ($sizes -join ', '))
