<!DOCTYPE html>
<html>
<head>
    <title>gar-create-klant1.php</title>
</head>
<body>
    <h1>garage create klant 1</h1>
    <p>
        Dit formulier wordt gebruikt om klantgegevens in te voeren
    </p>
    <form action="gar-create-klant2.php" method="post">
        klantnaam:      <input type="text" name="klantnaamvak">      <br />
        klantadres:     <input type="text" name="klantadresvak">     <br />
        klantpostcode:  <input type="text" name="klantpostcodevak">  <br />
        klantplaats:    <input type="text" name="klantplaatsvak">    <br />
        <input type="submit">
    </form>
    <?php
    echo "<a href='gar-menu.php'>Back to the GDM</a>";
    ?>
</body>
</html>