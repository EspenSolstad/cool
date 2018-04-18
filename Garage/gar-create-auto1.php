<!DOCTYPE html>
<html>
<head>
    <title>gar-create-auto1.php</title>
</head>
<body>
<h1>garage create auto 1</h1>
<p>
    Dit formulier wordt gebruikt om autogegevens in te voeren
</p>
<form action="gar-create-auto2.php" method="post">
    autokenteken:      <input type="text" name="autokentekenvak">      <br />
    automerk:     <input type="text" name="automerkvak">     <br />
    autotype:  <input type="text" name="autotypevak">  <br />
    autokmstand:    <input type="text" name="autokmstandvak">    <br />
    klantid:    <input type="text" name="klantidvak">    <br />
    <input type="submit">
</form>
<?php
echo "<a href='gar-menu.php'>Back to the GDM</a>";
?>
</body>
</html>