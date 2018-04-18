<!DOCTYPE html>
<html lang="en">
<head>
    <title>GCU</title>
</head>
<body>
<h1>Garage Car Updater</h1>
<p>
    This form let's you change the car data of the corresponding License plate.
</p>
<form action="gar-update-auto2.php" method="post">
    What License plate do you wish to change?
    <input type="text" name="autokentekenvak">  <br />
    <input type="submit">
</form>
<?php
echo "<a href='gar-menu.php'>Back to the GDM</a>";
?>
</body>
</html>