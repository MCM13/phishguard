$ErrorActionPreference = 'Continue'
$base = 'http://localhost:8000'

function Show-Headers($headers, $title) {
  Write-Host "`n--- $title ---" -ForegroundColor Cyan
  foreach ($k in @(
    'Strict-Transport-Security','X-Content-Type-Options','X-Frame-Options',
    'X-XSS-Protection','Referrer-Policy','Permissions-Policy','Content-Security-Policy'
  )) {
    if ($headers[$k]) { Write-Host "  $k = $($headers[$k])" }
    else              { Write-Host "  $k = (no presente)" -ForegroundColor Yellow }
  }
}

Write-Host "================================================================" -ForegroundColor Green
Write-Host "                   PHISHGUARD - SECURITY E2E" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green

# 1) Health + cabeceras
Write-Host "`n[1] Health check + cabeceras de seguridad" -ForegroundColor Green
$r = Invoke-WebRequest -Uri "$base/" -UseBasicParsing
Write-Host "  Status: $($r.StatusCode)"
Show-Headers $r.Headers "Headers en /"

# 2) Content-Type incorrecto -> 415
Write-Host "`n[2] Content-Type incorrecto en POST -> 415" -ForegroundColor Green
try {
  Invoke-WebRequest -Uri "$base/api/analyze/url" -Method POST -Body 'foo' -ContentType 'text/plain' -UseBasicParsing | Out-Null
} catch {
  $code = $_.Exception.Response.StatusCode.value__
  $stream = $_.Exception.Response.GetResponseStream()
  $reader = New-Object System.IO.StreamReader($stream)
  $body = $reader.ReadToEnd()
  Write-Host "  Status: $code"
  Write-Host "  Body: $body"
}

# 3) SSRF: URL apuntando a IP privada -> 400
Write-Host "`n[3] SSRF: POST con URL privada (192.168.0.1) -> 400" -ForegroundColor Green
try {
  Invoke-WebRequest -Uri "$base/api/analyze/url" -Method POST -ContentType 'application/json' -Body '{"url":"http://192.168.0.1/admin"}' -UseBasicParsing | Out-Null
} catch {
  $code = $_.Exception.Response.StatusCode.value__
  $stream = $_.Exception.Response.GetResponseStream()
  $reader = New-Object System.IO.StreamReader($stream)
  $body = $reader.ReadToEnd()
  Write-Host "  Status: $code"
  Write-Host "  Body: $body"
}

# 4) SSRF: localhost -> 400
Write-Host "`n[4] SSRF: localhost -> 400" -ForegroundColor Green
try {
  Invoke-WebRequest -Uri "$base/api/analyze/url" -Method POST -ContentType 'application/json' -Body '{"url":"http://localhost/secret"}' -UseBasicParsing | Out-Null
} catch {
  $code = $_.Exception.Response.StatusCode.value__
  Write-Host "  Status: $code (esperado 400)"
}

# 5) SSRF: metadata cloud -> 400
Write-Host "`n[5] SSRF: AWS metadata 169.254.169.254 -> 400" -ForegroundColor Green
try {
  Invoke-WebRequest -Uri "$base/api/analyze/url" -Method POST -ContentType 'application/json' -Body '{"url":"http://169.254.169.254/latest/meta-data/"}' -UseBasicParsing | Out-Null
} catch {
  $code = $_.Exception.Response.StatusCode.value__
  Write-Host "  Status: $code (esperado 400)"
}

# 6) Esquema no permitido -> 400
Write-Host "`n[6] Esquema no http(s) -> 400" -ForegroundColor Green
try {
  Invoke-WebRequest -Uri "$base/api/analyze/url" -Method POST -ContentType 'application/json' -Body '{"url":"ftp://example.com"}' -UseBasicParsing | Out-Null
} catch {
  $code = $_.Exception.Response.StatusCode.value__
  Write-Host "  Status: $code (esperado 400)"
}

# 7) Body > 1MB -> 413
Write-Host "`n[7] Body > 1MB -> 413" -ForegroundColor Green
$bigPayload = '{"content":"' + ('a' * 1200000) + '"}'
try {
  Invoke-WebRequest -Uri "$base/api/analyze/email" -Method POST -ContentType 'application/json' -Body $bigPayload -UseBasicParsing | Out-Null
} catch {
  $code = $_.Exception.Response.StatusCode.value__
  Write-Host "  Status: $code (esperado 413)"
}

# 8) Validacion Pydantic -> URL vacia / muy corta -> 422
Write-Host "`n[8] URL invalida (vacia) -> 422" -ForegroundColor Green
try {
  Invoke-WebRequest -Uri "$base/api/analyze/url" -Method POST -ContentType 'application/json' -Body '{"url":""}' -UseBasicParsing | Out-Null
} catch {
  $code = $_.Exception.Response.StatusCode.value__
  Write-Host "  Status: $code"
}

# 9) Rate limit: 11 peticiones a /api/analyze/url
Write-Host "`n[9] Rate limit: 11 peticiones consecutivas a /api/analyze/url" -ForegroundColor Green
$ok = 0; $rate = 0; $other = 0
for ($i = 1; $i -le 11; $i++) {
  try {
    $resp = Invoke-WebRequest -Uri "$base/api/analyze/url" -Method POST -ContentType 'application/json' -Body '{"url":"http://example.com/test"}' -UseBasicParsing -TimeoutSec 30
    Write-Host ("  Peticion {0,2}: HTTP {1}" -f $i, $resp.StatusCode)
    if ($resp.StatusCode -eq 200) { $ok++ } else { $other++ }
  } catch {
    $sc = $_.Exception.Response.StatusCode.value__
    Write-Host ("  Peticion {0,2}: HTTP {1}" -f $i, $sc) -ForegroundColor $(if ($sc -eq 429) { 'Yellow' } else { 'Red' })
    if ($sc -eq 429) {
      $rate++
      $stream = $_.Exception.Response.GetResponseStream()
      $reader = New-Object System.IO.StreamReader($stream)
      Write-Host "    Body: $($reader.ReadToEnd())"
    } else { $other++ }
  }
}
Write-Host "  --> OK=$ok  Rate-limited=$rate  Otros=$other" -ForegroundColor Cyan

# 10) /api/stats sigue funcionando
Write-Host "`n[10] /api/stats" -ForegroundColor Green
try {
  $r = Invoke-WebRequest -Uri "$base/api/stats" -UseBasicParsing
  Write-Host "  Status: $($r.StatusCode)"
  Write-Host "  Body: $($r.Content)"
} catch {
  Write-Host "  ERROR $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n================================================================" -ForegroundColor Green
Write-Host "                          FIN E2E" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
