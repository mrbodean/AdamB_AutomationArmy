$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.', '.'
. "$here\$sut"

Describe "FreelanceTest" {
    #Prepare the TestDrive 
    new-item -path "TestDrive:\Users" -ItemType directory
    new-item -path "TestDrive:\Users\U1" -ItemType directory
    new-item -path "TestDrive:\Users\U1\Folder" -ItemType directory
    new-item -path "TestDrive:\Users\U1\Folder\file.txt" -ItemType file
    new-item -path "TestDrive:\Users\U1\Folder\file.doc" -ItemType file
    new-item -path "TestDrive:\Users\U1\Foo" -ItemType directory
    new-item -path "TestDrive:\Users\U1\Foo\file.doc" -ItemType file

    new-item -path "TestDrive:\Users\U2" -ItemType directory
    new-item -path "TestDrive:\Users\U2\Foo" -ItemType directory
    new-item -path "TestDrive:\Users\U2\Foo\file.doc" -ItemType file

    new-item -path "TestDrive:\Users2" -ItemType directory
    new-item -path "TestDrive:\Users2\U1" -ItemType directory
    new-item -path "TestDrive:\Users2\U1\Bar" -ItemType directory
    new-item -path "TestDrive:\Users2\U1\Bar\file.xxx" -ItemType file

    new-item -path "TestDrive:\Users2\U3" -ItemType directory
    new-item -path "TestDrive:\Users2\U3\Baz" -ItemType directory
    new-item -path "TestDrive:\Users2\U3\Baz\file.abc" -ItemType file

    new-item -path "TestDrive:\Users3" -ItemType directory
    new-item -path "TestDrive:\Users3\U3" -ItemType directory
    new-item -path "TestDrive:\Users3\U3\U3" -ItemType directory
    new-item -path "TestDrive:\Users3\U3\U3\Foo" -ItemType directory
    new-item -path "TestDrive:\Users3\U3\U3\Foo\file.txt" -ItemType file

    new-item -path "TestDrive:\Users3\U1" -ItemType directory
    new-item -path "TestDrive:\Users3\U1\U1" -ItemType directory
    new-item -path "TestDrive:\Users3\U1\U1\Folder2" -ItemType directory
    new-item -path "TestDrive:\Users3\U1\U1\Folder2\file.doc" -ItemType file
    new-item -path "TestDrive:\Users3\U1\U1\Baz" -ItemType directory
    new-item -path "TestDrive:\Users3\U1\U1\Baz\file.doc" -ItemType file

    Context "Verify Test Setup" {
        It "Check that all file paths exists" {
            Test-Path "TestDrive:\Users\U1\Folder\file.txt"|Should Be $true
            Test-Path "TestDrive:\Users\U1\Folder\file.doc"|Should Be $true
            Test-Path "TestDrive:\Users\U1\Foo\file.doc"|Should Be $true
            Test-Path "TestDrive:\Users\U2\Foo\file.doc"|Should Be $true
            Test-Path "TestDrive:\Users2\U1\Bar\file.xxx"|Should Be $true
            Test-Path "TestDrive:\Users2\U3\Baz\file.abc"|Should Be $true
            Test-Path "TestDrive:\Users3\U3\U3\Foo\file.txt"|Should Be $true
            Test-Path "TestDrive:\Users3\U1\U1\Folder2\file.doc"|Should Be $true
            Test-Path "TestDrive:\Users3\U1\U1\Baz\file.doc"|Should Be $true
        }
    }
    
    $destination = "TestDrive:Destination"
    $source = "TestDrive:\Users","TestDrive:\Users2","TestDrive:\Users3"
    FreelanceTest -source $source -destination $destination -verbose

    Context "Verify End Results" {
        It "Check that all expected files are present" {
            Test-Path "TestDrive:\Destination\U1\Foo\file.doc"|Should Be $true
            Test-Path "TestDrive:\Destination\U1\Bar\file.xxx"|Should Be $true
            Test-Path "TestDrive:\Destination\U1\Baz\file.doc"|Should Be $true
            Test-Path "TestDrive:\Destination\U2\Foo\file.doc"|Should Be $true
            Test-Path "TestDrive:\Destination\U3\Baz\file.abc"|Should Be $true
        }
        It "Verify there are only 5 files in the Destination" {
            ((Get-ChildItem -Path "TestDrive:\Destination" -Recurse -file).count -eq 5)|Should Be $true   
        }
        It "Only copies the newest files" {
            $newdestfile = "TestDrive:\Destination\U1\Foo\file.doc"
            $newsourcefile = "TestDrive:\Users3\U1\U1\Baz\file.doc"
            $newsource_destfile = "TestDrive:\Destination\U1\Baz\file.doc"
            New-Item -Path $newdestfile -Force
            New-Item -Path $newsourcefile -Force
            $newdesttimestamp = (Get-ChildItem -Path $newdestfile).LastWriteTime
            $newsourcetimestamp = (Get-ChildItem -Path $newsourcefile).LastWriteTime
            $destination = "TestDrive:Destination"
            $source = "TestDrive:\Users","TestDrive:\Users2","TestDrive:\Users3"
            FreelanceTest -source $source -destination $destination -verbose
            (Get-ChildItem -Path $newdestfile).LastWriteTime| Should Be $newdesttimestamp
            (Get-ChildItem -Path $newsource_destfile).LastWriteTime| Should Be $newsourcetimestamp
        }
    }
}
