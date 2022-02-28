﻿#
# This script handles common telemetry tasks for Install.ps1 and Add-AppDevPackage.ps1.
#

function IsVsTelemetryRegOptOutSet()
{
    $VsTelemetryRegOptOutKeys = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\SQM",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM",
        "HKLM:\SOFTWARE\Microsoft\VSCommon\16.0\SQM"
    )

    foreach ($optOutKey in $VsTelemetryRegOptOutKeys)
    {
        if (Test-Path $optOutKey)
        {
            # If any of these keys have the DWORD value OptIn set to 0 that means that the user
            # has explicitly opted out of logging telemetry from Visual Studio.
            $val = (Get-ItemProperty $optOutKey)."OptIn"
            if ($val -eq 0)
            {
                return $true
            }
        }
    }

    return $false
}

try
{
    $TelemetryOptedOut = IsVsTelemetryRegOptOutSet
    if (!$TelemetryOptedOut)
    {
        $TelemetryAssembliesFolder = $args[0]
        $EventName = $args[1]
        $ReturnCode = $args[2]
        $ProcessorArchitecture = $args[3]

        foreach ($file in Get-ChildItem $TelemetryAssembliesFolder -Filter "*.dll")
        {
            [Reflection.Assembly]::LoadFile((Join-Path $TelemetryAssembliesFolder $file)) | Out-Null
        }

        [Microsoft.VisualStudio.Telemetry.TelemetryService]::DefaultSession.IsOptedIn = $True
        [Microsoft.VisualStudio.Telemetry.TelemetryService]::DefaultSession.Start()

        $TelEvent = New-Object "Microsoft.VisualStudio.Telemetry.TelemetryEvent" -ArgumentList $EventName
        if ($null -ne $ReturnCode)
        {
            $TelEvent.Properties["VS.DesignTools.SideLoadingScript.ReturnCode"] = $ReturnCode
        }

        if ($null -ne $ProcessorArchitecture)
        {
            $TelEvent.Properties["VS.DesignTools.SideLoadingScript.ProcessorArchitecture"] = $ProcessorArchitecture
        }

        [Microsoft.VisualStudio.Telemetry.TelemetryService]::DefaultSession.PostEvent($TelEvent)
        [Microsoft.VisualStudio.Telemetry.TelemetryService]::DefaultSession.Dispose()
    }
}
catch
{
    # Ignore telemetry errors
}
# SIG # Begin signature block
# MIIljwYJKoZIhvcNAQcCoIIlgDCCJXwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDJYj3WBgxKGoze
# wr0Sg8FHTlHGd5t93FeYNiZX9fYkC6CCC3IwggT6MIID4qADAgECAhMzAAAEOfYf
# emdtoACvAAAAAAQ5MA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTAwHhcNMjEwOTAyMTgyNTU4WhcNMjIwOTAxMTgyNTU4WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDYxnPFVXLjCNZotpu2pA/klQnh61TVmOwkp46L2lhfjh3H1JisbpZfdR7PSIOy
# thfERueQRQM4cYwlCHxZs2PJgVAWT1A09MgvyOnUu8+TP3rMJux8XpgfjbT1QY9W
# NvAV+9T/3+JaRgW+L/IarOJQ+fQx6fwoO8U1UDJykFo5fQIbgCGXO/uz69B0z6LE
# VrJP+qibVhromVIQ0vaip2Rh+EMlHNN3jDpuYJOfcI9iClLffv30NDVa7LNdr5S8
# 5uFW7WD6aVLd5Y4vytrD477um9drb3Xe/gXmBKUZ2JLMv+xZG39Xw/UbA1lQTN/t
# bof2MgifNoRRRRELlcOForTtAgMBAAGjggF5MIIBdTAfBgNVHSUEGDAWBgorBgEE
# AYI3PQYBBggrBgEFBQcDAzAdBgNVHQ4EFgQUxfAmBmr7eiyHypaAy6/f8G8lQsUw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzA4NjUrNDY3Mzk4MB8GA1UdIwQYMBaAFOb8
# X3u7IgBY5HJOtfQhdCMy5u+sMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwu
# bWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY0NvZFNpZ1BDQV8yMDEw
# LTA3LTA2LmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljQ29kU2lnUENBXzIwMTAtMDct
# MDYuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAGaOsNHOxecF
# hmUQiipJkW1uEeTTuKdpftxfnqFzxAqNngYLPDHQb3Ja8CnFNwCN5BFh21p4TM15
# Pv1aO+HCA3mYRAexP5LM9mTTBEoC5WFMNVG+6x138G/BnafTHRIj5UjgZHWR3t2s
# /uWoNBRtTYVUKTdwuvh+2bCeJrEebuWi4cOOkHd3eBwaD+Dh/iJinmdUoYoAA8cN
# AnZ+4jsirVYsvnfHeYtzEPVUPFtRVsHSRhs+zMpm+66oju2d8z2HHS3Q+OVgbCXq
# BAg1c+BTzV9+9oaMXuq7klKeRNj1quZae0jisxP+fxQx3iWB7I8YVx0EmGg67aQS
# pjH84cst2PswggZwMIIEWKADAgECAgphDFJMAAAAAAADMA0GCSqGSIb3DQEBCwUA
# MIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQD
# EylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0x
# MDA3MDYyMDQwMTdaFw0yNTA3MDYyMDUwMTdaMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDpDmRQ
# eWe1xOP9CQBMnpSs91Zo6kTYz8VYT6mldnxtRbrTOZK0pB75+WWC5BfSj/1EnAjo
# ZZPOLFWEv30I4y4rqEErGLeiS25JTGsVB97R0sKJHnGUzbV/S7SvCNjMiNZrF5Q6
# k84mP+zm/jSYV9UdXUn2siou1YW7WT/4kLQrg3TKK7M7RuPwRknBF2ZUyRy9HcRV
# Yldy+Ge5JSA03l2mpZVeqyiAzdWynuUDtWPTshTIwciKJgpZfwfs/w7tgBI1TBKm
# vlJb9aba4IsLSHfWhUfVELnG6Krui2otBVxgxrQqW5wjHF9F4xoUHm83yxkzgGqJ
# TaNqZmN4k9Uwz5UfAgMBAAGjggHjMIIB3zAQBgkrBgEEAYI3FQEEAwIBADAdBgNV
# HQ4EFgQU5vxfe7siAFjkck619CF0IzLm76wwGQYJKwYBBAGCNxQCBAweCgBTAHUA
# YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# 1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIw
# MTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcnQwgZ0GA1UdIASBlTCBkjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUF
# BwIBFjFodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1
# bHQuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5
# AF8AUwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAadO9X
# Tyl7xBaFeLhQ0yL8CZ2sgpf4NP8qLJeVEuXkv8+/k8jjNKnbgbjcHgC+0jVvr+V/
# eZV35QLU8evYzU4eG2GiwlojGvCMqGJRRWcI4z88HpP4MIUXyDlAptcOsyEp5aWh
# aYwik8x0mOehR0PyU6zADzBpf/7SJSBtb2HT3wfV2XIALGmGdj1R26Y5SMk3YW0H
# 3VMZy6fWYcK/4oOrD+Brm5XWfShRsIlKUaSabMi3H0oaDmmp19zBftFJcKq2rbty
# R2MX+qbWoqaG7KgQRJtjtrJpiQbHRoZ6GD/oxR0h1Xv5AiMtxUHLvx1MyBbvsZx/
# /CJLSYpuFeOmf3Zb0VN5kYWd1dLbPXM18zyuVLJSR2rAqhOV0o4R2plnXjKM+zeF
# 0dx1hZyHxlpXhcK/3Q2PjJst67TuzyfTtV5p+qQWBAGnJGdzz01Ptt4FVpd69+lS
# TfR3BU+FxtgL8Y7tQgnRDXbjI1Z4IiY2vsqxjG6qHeSF2kczYo+kyZEzX3EeQK+Y
# Zcki6EIhJYocLWDZN4lBiSoWD9dhPJRoYFLv1keZoIBA7hWBdz6c4FMYGlAdOJWb
# HmYzEyc5F3iHNs5Ow1+y9T1HU7bg5dsLYT0q15IszjdaPkBCMaQfEAjCVpy/JF1R
# Ap1qedIX09rBlI4HeyVxRKsGaubUxt8jmpZ1xTGCGXMwghlvAgEBMIGVMH4xCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jv
# c29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTACEzMAAAQ59h96Z22gAK8AAAAABDkw
# DQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIP0IUOM
# BJw0eRiT2Osp18eCU/zvQ83hW8jMkUFKv3nYMEIGCisGAQQBgjcCAQwxNDAyoBSA
# EgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20w
# DQYJKoZIhvcNAQEBBQAEggEA115tsHCewTF4hU44tphLBnOOhdub2ifHCP/SB0E2
# 8Fzwk9HF0aI8p7oYjS+x82yleLUbzybsO+0tK6EQr+yb2Um6SGkDuA/NuNDEnLvw
# xJodMLW2UAIOyp/EVcfmdbwAfDtUTdaSv/KSDlbXGnXS9syvxQ65cEGzEYbN7olm
# 2poV9oGDpOFCmDoX975Ko+OxNdO+0CrwpIHlLrx/z0WIEcjE9x2x3oD2h8ZafyYR
# Hn2f2+Hn50rZu/qPY6Bosbn02Ry3ZeB5PfQ1VAzX4YC/kBfREHWEHCh1W/7mPq6z
# i/rDvxBNPiJjqYt3hSlGiOlGIoJG//C6KkzkoteryhRIeqGCFv0wghb5BgorBgEE
# AYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUD
# BAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoD
# ATAxMA0GCWCGSAFlAwQCAQUABCABxD2wLwTQSszq4f9kKgRzVivXf0pTe5z4OPWx
# kWn+VwIGYfraTd48GBMyMDIyMDIxMDIwMzkxNS45MzRaMASAAgH0oIHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjoyMjY0LUUzM0UtNzgwQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaCCEVQwggcMMIIE9KADAgECAhMzAAABmHazjMXQBaEBAAEAAAGY
# MA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4X
# DTIxMTIwMjE5MDUxNVoXDTIzMDIyODE5MDUxNVowgcoxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNh
# IE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjIyNjQtRTMzRS03
# ODBDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxtSVrFZLKfMRuLCzJ38X4rd0oSPu
# xtTH00/uV70M7gDnvK+TEQBSE05oxcc6CxX5msS7z1ZZg4JA4tK6rDrPQJfY1cGE
# hVRf8Fgtvge+jsrIskY8PjT4+QOHJjIT6iHTZESwhPsLbiP8Amqt/y3+JKAxrnSH
# BGEYDKqk6DjlCFeHuxHWG95Pa2Dze0rJcLCxUqfhb5v0HMuSqn5JjF+Et6Ccex3Y
# kISmytQumX4m/u+tW5q3Ty0+nnXZZ8sJbO4QqyCLhbYFG1I+iiSGZ9TG2GPIawDO
# fbby6XhphVtxo3gQJrwcQJ+6PS6dp8pE9cPSNLPXXcKRZ4y09jyu+Bg0rMRVGRtV
# LS8qYv5GXIPVnpzwGaVLTxXzuTLYn/CWvI11yyD+ivm+S4kFfKCMRUgX4BTe/0y9
# rUkn0FXL6l9ZnEjq8f7bIKty+mAMSOj5eIdc0K3AJk6MqRKD2DXP0ZUgZOpY5jcj
# Q7F94LSvKenOxwllIRfmIzIH2p0JjI1GLG43RLAsi+kAKI2dH+pLXjeHFeqGxcHF
# BL4mMoFm3nWk/OjhnvSxDsT7oc4Bb9maG1a9CfIZdRVXXGRW3xTf4HYx2f53Aw6i
# zVoHKDKBIcMM6OxQDm6imsXwecwgamEo+OZojTuYN4T/AIAtHkgh5d6yuyTzK9Qf
# vCUx7cEZEis//nMCAwEAAaOCATYwggEyMB0GA1UdDgQWBBRukYRyjabIN5oKJ7Oy
# 0eWB083hNzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8E
# WDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9N
# aWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYB
# BQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEw
# KDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqG
# SIb3DQEBCwUAA4ICAQAk+gehd94v/Pc104KkPC+gmDB8fQYmhzlfsJOdyTq4gs3m
# i42IEcrLCYZp5yfwnR2uao3EsL0abVqWST1SubMYTiI0QT4LP9/hEdL0vOyAPmhm
# 3+zRey2WZcVjzpf8hQYPamd7aThjqIUCJ0J+c6Vdt4VqKWjeHOPYxiRyzwH8vbu/
# mUhkLsNeArFv10SxCx09fCOtFtLijgWuT5tlYqITKL3G6TVAhBEaiDvVj8MyMDEU
# cN+Py4I7rJRyaKfv9VXvwn8jasHlJsHqUBya3fsEy1JYJuBDW1xeoudoxX2KREsC
# 3QJ+eqP6Y/oK7Hdi6wBD0EcoePa1ryP6mXzobU9hVpsxcOiCb2ews09TvhXNICAw
# TamrLOUG5pDpCmMvVO5xQOqp92WfjK2TLCU4+4MQH9MjJFasGFmUZOG62PavCQz5
# nHzUo0a1X6WMsxFRKnphmp5sbww080tsJEgWt83DcDoGIVgU5iXS4MoliRnqso9Z
# uW8DYJzsOjc1wolTM3287XZKjnU0fPC7QCRjUY3r1o0HeV4rRrnoEqdpjCYJRc0c
# JJ3EGrtQSbAo/9Wg2OKDIjvHKJ5Jmlga2HtdUAkvPev7GcEnZxFCWpNKqZwURQfk
# x0SMSIrwijW8RtkEWfHYfeXDl4KNGLwTeWtafoid7zcM53lNgCAu8966yGzdnzCC
# B3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAw
# gYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMT
# KU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIx
# MDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57Ry
# IQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VT
# cVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhx
# XFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQ
# HJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1
# KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s
# 4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUg
# fX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3
# Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je
# 1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUY
# hEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUY
# P3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGC
# NxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4w
# HQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYB
# BAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcD
# CDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0T
# AQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNV
# HR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9w
# cm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEE
# TjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOC
# AgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/a
# ZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp
# 4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq
# 95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qB
# woEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG
# +jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3B
# FARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77
# IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJ
# fn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K
# 6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDx
# yKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLLMIICNAIBATCB
# +KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEl
# MCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMd
# VGhhbGVzIFRTUyBFU046MjI2NC1FMzNFLTc4MEMxJTAjBgNVBAMTHE1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAPMsHv4heTPHyFNm
# k+skN75z6VeToIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAw
# DQYJKoZIhvcNAQEFBQACBQDlr+RtMCIYDzIwMjIwMjExMDMyMjIxWhgPMjAyMjAy
# MTIwMzIyMjFaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOWv5G0CAQAwBwIBAAIC
# C08wBwIBAAICEVcwCgIFAOWxNe0CAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYB
# BAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOB
# gQCCXfxb9fG5nVEuPXJZK7mBv6sA2BFwAoveuklQt3M9HaZkjgmi/davTdP4oUR1
# rlSGvs+L5lq2Wg3X6Y7wNbEqn3o6sx/l807SsOs7YTf1spZvuBh1vYis/CmOyjqY
# tlJr2s0YbyGjM+YJLwR2K9lwYvqXXO6uazOvB4EvGca6PjGCBA0wggQJAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABmHazjMXQBaEBAAEA
# AAGYMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEII0r/zfgEl3rVy1uz62zI/FUSo0dPG6nHzw2WDhi
# pgw1MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgv6bOBjk5//cDtTYRzPUH
# 3tJaAd7JZMNRRd6/m4dtVsQwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAZh2s4zF0AWhAQABAAABmDAiBCAeECy0zqvWL/Sx/dVBQ2dE
# ihnCv9TpKEgJk/gaWcCWtDANBgkqhkiG9w0BAQsFAASCAgCtdUGoo+nMf6rUt7IY
# JhCxb8BgJU4Uz4u2POCB4pjcvGkW+TZ5TX81+P9eBDTG5ZAtMfqjXb6UiF3jsJjO
# UVwyVA56ABYEmR9j5YGmBWcpnXtS4+WzsgWOyoJhk5vwT7cSNyVbwOt5GakDFPAg
# GlVvChc4EDftMM0Rva2S72zXyuUCd+WXoPRNKRbKjSlC0v/ZptbFO/epvm8N1eqO
# 6iyrqMi2ekbNdboJBSa3VtWEB3MCfLWVw0iXyeVExwa22zBN+QZt+UHvbVDtFrXV
# TcTWJW0VaxjcOw38y3F1V0HUnxjzSE6Nhuo0SpzEY3AMzRxM0SaCjha3O2v79IZ4
# Unq2eFL/othXtKMh74ebY5IWR0ZH9blo7PTjhU2DVrF7YEczEswF5GWk4gpM9RBD
# ol/J+hbXFQjNYKdSeYW9Xq8aMEwMbU/hzQ8uMKut0ugYFxP0MW/6FNDbT9KhpV9r
# a9pQ8O7vZbcaTYz142PrQ3glPg5Vq7r4vAJTUGjj4pF/H75B2EySOKwhH27Zdk38
# f9IC9/pzSOcnuToLpOGzjZ+DBwij/Haa6k9UTAmsuGtmoIEbI6JnaKf+ox0ucgOm
# CRd0wrs50Mr6sHeQO6DZ9JtXy6uebWwQrLqqitqClWngO2yuG/rSgkwEtuUwUXAC
# BqesJouBerOpK8VFcrXaQAjC9g==
# SIG # End signature block