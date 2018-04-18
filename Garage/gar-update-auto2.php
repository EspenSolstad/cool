<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="author " content="Espen Solstad">
    <meta charset="UTF-8">
    <title>GCU</title>
</head>
<body>
<h1>Garage Car Updater</h1>
<p>
    This form is used to update Car Data.
</p>
<?php
// klantid uit het formulier halen ----------------------------
$autokenteken = $_POST["autokentekenvak"];

// klantgegevens uit de tabel halen ---------------------------
require_once "gar-connect.php";

$autokentekenvak = $conn->prepare("
select  autokenteken,
        automerk,
        autotype,
        autokmstand,
        klantid
from    auto
where   autokenteken = :autokenteken
");
$autokentekenvak->execute(["autokenteken" => $autokenteken]);

// klantgegevens in een nieuw formulier laten zien ---------------
echo "<form action='gar-update-auto3.php' method='post'>";
foreach($autokentekenvak as $auto)
{
    // klantid mag niet gewijzigd worden
    echo "klantid:";
    echo " <input type='text' name='klantidvak' ";
    echo " value = '" .$auto["klantid"]. "' ";
    echo "> <br /> ";

    echo " automerk: <input type='text' ";
    echo " name  = 'automerkvak' ";
    echo " value = '" .$auto["automerk"]. "' ";
    echo " > <br />";

    echo " autotype: <input type='text' ";
    echo " name  = 'autotypevak' ";
    echo " value = '" .$auto["autotype"]. "' ";
    echo " > <br />";

    echo " autokmstand: <input type='text' ";
    echo " name  = 'autokmstandvak' ";
    echo " value = '" .$auto["autokmstand"]. "' ";
    echo " > <br />";

    echo " autokenteken:" . $auto["autokenteken"]. "<input type='hidden' ";
    echo " name  = 'autokentekenvak' ";
    echo " value = '" .$auto["autokenteken"]. "' ";
    echo " > <br />";
}
echo "<input type='submit'>";
echo "</form>";

// er moet eigenlijk nog gecontroleerd worden op een bestaand klantid
?>
</body>
</html>