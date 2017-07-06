function FreelanceTest {
    [CmdletBinding()]
    Param
    (
        #Source Path
        [Parameter(Mandatory=$true)]
        [string[]]$Source,
        #Destination Path
        [Parameter(Mandatory=$true)]
        [string]$destination
    )
    Begin{
        $Excludedfiletypes = "*.txt","*.pdf"
        $Includeddirectories = "Foo","Bar","Baz"
        if(!(Test-path -path $destination)){
            Write-Verbose "$destination was not found it will be created"
            try{New-Item -Path $destination -ItemType Directory}
            catch{
                Throw "Unable to create $destination"
                return
            }
        }
    }
    Process{
        Foreach($path in $Source){
            Write-Verbose "Ensure $path is accessable"
            If(Test-Path -Path $path){
                $sourcedirectories = Get-ChildItem -Path $path -Include $Includeddirectories -Recurse -Directory
                    Write-Verbose "Found $($sourcedirectories.count)"
                $sourcefiles = Get-ChildItem -Path $sourcedirectories -Exclude $Excludedfiletypes -Recurse -File
                foreach($file in $sourcefiles){
                    Write-Verbose "processing $file"
                    $2levelparent = $file.psparentpath.split('\')
                    $count = $2levelparent.count
                    $2levelparent = "$($2levelparent[($count-2)])\$($2levelparent[($count-1)])"
                    Write-Verbose "Profile parent path is $2levelparent"
                    $destinationpath = Join-Path -Path $destination -ChildPath $2levelparent
                    if(!(Test-Path $destinationpath)){
                        Write-Verbose "$destinationpath was not found. Creating the directory."
                        New-Item -Path $destinationpath -ItemType Directory -Force
                        }
                    $destinationfilepath = Join-Path -Path $destinationpath -ChildPath $file.name
                    if(Test-path -Path $destinationfilepath){
                        Write-Verbose "$destinationfilepath was found. Check to see if the source is newer."
                        $existingfile = Get-ChildItem -Path $destinationfilepath
                        if($file.LastWriteTime -gt $existingfile.LastWriteTime){
                            Write-Verbose "$($file.fullname) is newer and will be copied."
                            try{Copy-Item -Path $file.fullname -Destination $destinationpath -Force}
                            catch{
                                Write-Error "Error copying $($file.fullname) to $destinationpath"
                            }
                        }else{
                            Write-Verbose "$($existingfile.fullname) is newer and will not be replaced."
                        }
                    }else{
                        Write-Verbose "$($file.fullname) will be copied to $destinationpath"
                        try{Copy-Item -Path $file.fullname -Destination $destinationpath}
                        catch{
                            Write-Error "Error copying $($file.fullname) to $destinationpath"
                        }
                    }
                }
            }else{
                Write-Warning "Unable to access $path !!! It will not be processed!!!"
            }
        }

    }
}
