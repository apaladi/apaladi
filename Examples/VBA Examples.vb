'concatenate range with delimiter in Office 2016
' (in Office365 can use TEXTJOIN)

'1. Developer -> Insert Module 
Function CONCATENATEMULTIPLE(Ref As Range, Separator As String) As String
    Dim Cell As Range
    Dim Result As String
    For Each Cell In Ref
        If Not IsEmpty(Cell.Value) Then Result = Result & Cell.Value & Separator
    Next Cell
    CONCATENATEMULTIPLE = Left(Result, Len(Result) - 1)
End Function

'2. Paste the range as one column and remove the duplicates
'3. Run the function as a cell formula
=CONCATENATEMULTIPLE(Table1[[Details_Table0_SMSSiteName]],";")
=CONCATENATEMULTIPLE(Table1[[Details_Table0_SMSSiteName]:[Details_Table0_TopConsoleUser]],";")




