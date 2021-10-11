library libraiden;

{$Q-}
{$R-}

(*************************************************************************

Raiden cipher pascal port

(c) 2009 Alexander Myasnikow

Web: www.darksoftware.narod.ru


**************************************************************************)


type
  tdatablock = array [0..1] of longword;
type
  pdatablock = ^Tdatablock;
type
  t2datablock = array [0..1] of tdatablock;
type
  p2datablock = ^T2datablock;
type
  tkeyblock = array [0..3] of longword;
type
  pkeyblock = ^Tkeyblock;


  procedure crypt2 (Data: tdatablock; var Result: tdatablock; key: pkeyblock); stdcall;
  var
    b0: longword;
    b1: longword;
    i:  longword;
    sk: array [0..15] of longword;
    k:  tkeyblock;
  begin

    b0 := Data[0];
    b1 := Data[1];

    move(key^, k[0], 16);


    for I := 0 to 15 do
      begin
      k[i mod 4] := ((k[0] + k[1]) + ((k[2] + k[3]) xor (k[0] shl k[2])));
      sk[i] := k[i mod 4];
      end;

    for i := 0 to 15 do
      begin
      b0 := b0 + (((sk[i] + b1) shl 9) xor ((sk[i] - b1) xor ((sk[i] + b1) shr 14)));
      b1 := b1 + (((sk[i] + b0) shl 9) xor ((sk[i] - b0) xor ((sk[i] + b0) shr 14)));
      end;

    Result[0] := b0;
    Result[1] := b1;

  end;


  procedure crypt (Data: p2datablock; Result: p2datablock; key: pkeyblock);
  stdcall; export;
  begin
    crypt2(Data[0], Result[0], key);
    crypt2(Data[1], Result[1], key);
  end;


  procedure decrypt2 (Data: tdatablock; var Result: tdatablock;
    key: pkeyblock); stdcall;
  var
    b0: longword;
    b1: longword;
    i:  longword;
    sk: array [0..15] of longword;
    k:  tkeyblock;
  begin

    b0 := Data[0];
    b1 := Data[1];

    move(key^, k[0], 16);


    for I := 0 to 15 do
      begin
      k[i mod 4] := ((k[0] + k[1]) + ((k[2] + k[3]) xor (k[0] shl k[2])));
      sk[i] := k[i mod 4];
      end;

    for i := 15 downto 0 do
      begin
      b1 := b1 - (((sk[i] + b0) shl 9) xor ((sk[i] - b0) xor ((sk[i] + b0) shr 14)));
      b0 := b0 - (((sk[i] + b1) shl 9) xor ((sk[i] - b1) xor ((sk[i] + b1) shr 14)));
      end;
    Result[0] := b0;
    Result[1] := b1;

  end;


  procedure decrypt (Data: p2datablock; Result: p2datablock; key: pkeyblock);
  stdcall; export;
  begin
    decrypt2(Data[0], Result[0], key);
    decrypt2(Data[1], Result[1], key);
  end;


exports
  crypt,
  decrypt;

end.