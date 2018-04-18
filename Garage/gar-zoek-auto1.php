<!DOCTYPE html>
<html lang="nl">
<head>
    <title>GCS</title>
</head>
<body>
<h1>Garage Car Searcher</h1>
<p>
    This form searches for a specific car in the database using the corresponding License plate.
</p>
<form action="gar-zoek-auto2.php" method="post">
    What License plate are you searching for?
    <input type="text" name="autokentekenvak">  <br />
    <input type="submit">
</form>
<?php
echo "<a href='gar-menu.php'>Back to the GDM</a>";
?>
</body>
</html>