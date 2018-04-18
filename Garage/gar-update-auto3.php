<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="author" content="Espen Solstad"
    <meta charset="UTF-8">
    <title>GCU</title>
</head>
<body>
<h1>Garage Car Updater</h1>
<p>
    Change Car Data.
</p>
<?php
// klantgegevens uit het formulier halen -----------------------------
$autokenteken        = $_POST["autokentekenvak"];
$automerk      = $_POST["automerkvak"];
$autotype     = $_POST["autotypevak"];
$autokmstand  = $_POST["autokmstandvak"];
$klantid    = $_POST["klantidvak"];

// updaten klantgegevens ---------------------------------------------
require_once "gar-connect.php";

$sql = $conn->prepare
("
update auto set
                  automerk    = :automerk,
                  autotype = :autotype,
                  autokmstand   = :autokmstand,
                  klantid       = :klantid
                  where autokenteken = :autokenteken
");

$sql->execute
([
    "autokenteken"       => $autokenteken,
    "automerk"     => $automerk,
    "autotype"    => $autotype,
    "autokmstand" => $autokmstand,
    "klantid"   => $klantid
]);

echo "The car data has been updated.<br />";
echo "<a href='gar-menu.php'>Back to the GDM</a>";
?>
</body>
</html>