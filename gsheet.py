import gspread

sa = (
    gspread.service_account()
)  # if json file move to another location, put that in the ()
sh = sa.open("PSIRTs")

wks = sh.worksheet("Last7")

# print("Rows: ", wks.row_count)
# print("Cols: ", wks.col_count)

# print(wks.acell("A5").value)

# print(wks.cell(2, 3).value)

# print(wks.get("A2:J2"))

# print(wks.get_all_records())
# print(wks.get_all_values())

# wks.update("A10", "Update")

# wks.update("A12:B13", [["A12", "A13"], ["B12", "B13"]])

# wks.update("A17", "=UPPER('H2')", raw=False)   #Does not work

# wks.delete_rows(17)

wks.clear()
