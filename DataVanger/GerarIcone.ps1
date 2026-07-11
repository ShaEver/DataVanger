# GerarIcone.ps1 — Gera app.ico (16x16, 32x32, 48x48) com escudo ciano e letra "D"
# Requer .NET (System.Drawing) — disponivel em qualquer Windows com .NET instalado

Add-Type -AssemblyName System.Drawing

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$outPath   = Join-Path $scriptDir "app.ico"

function New-IconBitmap([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size)
    $g   = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode   = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::Transparent)

    $cyan  = [System.Drawing.Color]::FromArgb(255, 0, 187, 221)
    $dark  = [System.Drawing.Color]::FromArgb(255, 0,  90, 110)
    $white = [System.Drawing.Color]::White

    # Escudo: poligono hexagonal com base arredondada
    $m  = [float]($size * 0.08)
    $w  = [float]($size - 2 * $m)
    $h  = [float]($size - 2 * $m)
    $cx = [float]($size / 2.0)
    $cy = [float]($size / 2.0)

    # Pontos do escudo (topo plano, lados inclinados, ponta na base)
    $pts = [System.Drawing.PointF[]]@(
        [System.Drawing.PointF]::new($m,          $m),
        [System.Drawing.PointF]::new($m + $w,     $m),
        [System.Drawing.PointF]::new($m + $w,     $m + $h * 0.55),
        [System.Drawing.PointF]::new($cx,         $m + $h),
        [System.Drawing.PointF]::new($m,          $m + $h * 0.55)
    )

    $brush  = New-Object System.Drawing.SolidBrush($cyan)
    $pen    = New-Object System.Drawing.Pen($dark, [float]([Math]::Max(1, $size * 0.04)))
    $g.FillPolygon($brush, $pts)
    $g.DrawPolygon($pen, $pts)

    # Letra "D" centralizada
    $fontSize = [float]($size * 0.45)
    $font     = New-Object System.Drawing.Font("Segoe UI", $fontSize,
                    [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $sf       = New-Object System.Drawing.StringFormat
    $sf.Alignment     = [System.Drawing.StringAlignment]::Center
    $sf.LineAlignment = [System.Drawing.StringAlignment]::Center
    $rect = [System.Drawing.RectangleF]::new(0, [float]($size * 0.02), [float]$size, [float]($size * 0.82))
    $wbrush = New-Object System.Drawing.SolidBrush($white)
    $g.DrawString("D", $font, $wbrush, $rect, $sf)

    $g.Dispose()
    $font.Dispose()
    return $bmp
}

# Gera os 3 tamanhos
$sizes  = @(16, 32, 48)
$bitmaps = $sizes | ForEach-Object { New-IconBitmap $_ }

# Monta ICO manualmente (formato ICO simples, PNG comprimido por tamanho)
$ms = New-Object System.IO.MemoryStream

# Converte cada bitmap para PNG em memória
$pngs = $bitmaps | ForEach-Object {
    $tmp = New-Object System.IO.MemoryStream
    $_.Save($tmp, [System.Drawing.Imaging.ImageFormat]::Png)
    $tmp.ToArray()
}

# ICO header: ICONDIR
$writer = New-Object System.IO.BinaryWriter($ms)
$writer.Write([uint16]0)          # reserved
$writer.Write([uint16]1)          # type: ICO
$writer.Write([uint16]$sizes.Count)

# Calcula offsets: header (6) + entries (16 * count) + dados anteriores
$dataOffset = 6 + 16 * $sizes.Count
$offsets = @()
foreach ($png in $pngs) {
    $offsets += $dataOffset
    $dataOffset += $png.Length
}

# ICONDIRENTRY para cada tamanho
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $sz  = $sizes[$i]
    $png = $pngs[$i]
    $writer.Write([byte]$(if ($sz -ge 256) { 0 } else { $sz }))   # width
    $writer.Write([byte]$(if ($sz -ge 256) { 0 } else { $sz }))   # height
    $writer.Write([byte]0)        # color count
    $writer.Write([byte]0)        # reserved
    $writer.Write([uint16]1)      # planes
    $writer.Write([uint16]32)     # bit count
    $writer.Write([uint32]$png.Length)
    $writer.Write([uint32]$offsets[$i])
}

# Dados PNG
foreach ($png in $pngs) {
    $writer.Write($png)
}

$writer.Flush()
[System.IO.File]::WriteAllBytes($outPath, $ms.ToArray())

$bitmaps | ForEach-Object { $_.Dispose() }
$ms.Dispose()

Write-Host "app.ico gerado em: $outPath"
