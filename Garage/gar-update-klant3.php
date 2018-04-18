<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="author" content="Espen Solstad"
    <meta charset="UTF-8">
    <title>GCU</title>
</head>
<body>
<h1>Garage Customer Updater</h1>
<p>
    Succesfully updated customer data!
</p>
<?php
// klantgegevens uit het formulier halen -----------------------------
$klantid        = $_POST["klantidvak"];
$klantnaam      = $_POST["klantnaamvak"];
$klantadres     = $_POST["klantadresvak"];
$klantpostcode  = $_POST["klantpostcodevak"];
$klantplaats    = $_POST["klantplaatsvak"];

// updaten klantgegevens ---------------------------------------------
require_once "gar-connect.php";

$sql = $conn->prepare
("
update klant set  klantnaam     = :klantnaam,
                  klantadres    = :klantadres,
                  klantpostcode = :klantpostcode,
                  klantplaats   = :klantplaats
                  where klantid = :klantid
");

$sql->execute
([
    "klantid"       => $klantid,
    "klantnaam"     => $klantnaam,
    "klantadres"    => $klantadres,
    "klantpostcode" => $klantpostcode,
    "klantplaats"   => $klantplaats
]);

echo "<br />";
echo "<a href='gar-menu.php'>Back to the GDM</a>";
?>
</body>
</html>
