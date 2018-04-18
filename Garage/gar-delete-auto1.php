<!DOCTYPE html>
<html lang="en">
<head>
    <title>gar-delete-auto1.php</title>
</head>
<body>
<h1>garage delete auto 1</h1>
<p>
    Dit formulier zoekt een auto op uit
    de tabel auto's van database garage
    om hem te kunnen verwijderen.
</p>
<form action="gar-delete-auto2.php" method="post">
    Welk Kenteken wilt u verwijderen?
    <input type="text" name="autokentekenvak"> <br />
    <input type="submit">
</form>
<?php
echo "<a href='gar-menu.php'>Back to the GDM</a>";
?>
</body>
</html>