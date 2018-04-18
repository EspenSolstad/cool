<!DOCTYPE html>
<html lang="en">
<head>
    <title>gar-delete-auto2.php</title>
</head>
<body>
<h1>garage delete auto 2</h1>
<p>
    Op auto gegevens zoeken uit de
    tabel auto's van de database garage
    zodat ze verwijderd kunnen worden.
</p>
<?php
// klantid uit het formulier halen -----------------------------
$autokenteken = $_POST["autokentekenvak"];

// klantgegevens uit de tabel halen ----------------------------
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

// klantgegevens laten zien -------------------------------------
echo "<table>";
foreach ($autokentekenvak as $auto)
{
    echo "<tr>";
    echo "<td>"  .$auto["autokenteken"]       . "</td>";
    echo "<td>"  .$auto["automerk"]     . "</td>";
    echo "<td>"  .$auto["autotype"]    . "</td>";
    echo "<td>"  .$auto["autokmstand"] . "</td>";
    echo "<td>"  .$auto["klantid"]   . "</td>";
    echo "</tr>";
}
echo "</table><br />";

echo "<form action='gar-delete-auto3.php' method='post'>";
// klantid mag niet meer geqijzigd worden
echo "<input type='hidden' name='autokentekenvak' value=$autokenteken>";
// Waarde 0 doorgegeven als er niet gecheckt wordt
echo "<input type='hidden' name='verwijdervak' value='0'>";
echo "<input type='checkbox' name='verwijdervak' value='1'>";
echo "Delete this Car.<br />";
echo "<input type='submit'>";
echo "</form>";
?>
</body>
</html>